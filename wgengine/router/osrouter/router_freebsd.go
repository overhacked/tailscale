// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package osrouter

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tailscale/wireguard-go/tun"
	"tailscale.com/health"
	"tailscale.com/net/netmon"
	"tailscale.com/types/logger"
	"tailscale.com/util/backoff"
	"tailscale.com/wgengine/router"
)

func init() {
	router.HookNewUserspaceRouter.Set(func(opts router.NewOpts) (router.Router, error) {
		return newFreeBSDRouter(opts.Logf, opts.Tun, opts.NetMon, opts.Health)
	})
	router.HookCleanUp.Set(func(logf logger.Logf, netMon *netmon.Monitor, ifName string) {
		cleanUp(logf, ifName)
	})
}

// freebsdRouter extends the shared BSD userspace router with FreeBSD-specific
// IP forwarding and PF-based NAT for native subnet routing.
type freebsdRouter struct {
	*userspaceBSDRouter
	snatSubnetRoutes bool
}

func newFreeBSDRouter(logf logger.Logf, tundev tun.Device, netMon *netmon.Monitor, health *health.Tracker) (router.Router, error) {
	bsd, err := newUserspaceBSDRouter(logf, tundev, netMon, health)
	if err != nil {
		return nil, err
	}
	return &freebsdRouter{userspaceBSDRouter: bsd}, nil
}

func (r *freebsdRouter) Set(cfg *router.Config) (reterr error) {
	if cfg == nil {
		cfg = &shutdownConfig
	}

	setErr := func(err error) {
		if reterr == nil {
			reterr = err
		}
	}

	// Base address and route management.
	if err := r.userspaceBSDRouter.Set(cfg); err != nil {
		setErr(err)
	}

	// Enable IP forwarding when advertising subnet routes.
	if len(cfg.SubnetRoutes) > 0 {
		r.enableIPForwarding()
	}

	// Manage PF NAT rules for subnet routing.
	switch {
	case cfg.SNATSubnetRoutes == r.snatSubnetRoutes:
		// No change needed.
	case cfg.SNATSubnetRoutes:
		if err := r.addPFNATRules(); err != nil {
			r.logf("adding PF NAT rules: %v", err)
			setErr(err)
		}
	default:
		if err := r.delPFNATRules(); err != nil {
			r.logf("removing PF NAT rules: %v", err)
			setErr(err)
		}
	}
	r.snatSubnetRoutes = cfg.SNATSubnetRoutes

	return reterr
}

func (r *freebsdRouter) enableIPForwarding() {
	for _, kv := range []string{
		"net.inet.ip.forwarding=1",
		"net.inet6.ip6.forwarding=1",
	} {
		if out, err := cmd("sysctl", kv).CombinedOutput(); err != nil {
			r.logf("warning: sysctl %s: %v (%s)", kv, err, strings.TrimSpace(string(out)))
		}
	}
}

// pfAnchorName is the PF anchor used for all Tailscale NAT/filter rules.
// Using an anchor keeps our rules isolated from the user's existing PF
// configuration; we only ever flush or modify rules inside this anchor.
const pfAnchorName = "tailscale"

// Flag to determine whether PF anchors were added and should be removed during cleanUp
var shouldCleanupPfAnchors atomic.Bool

// Maximum number of retries to modify the PF main ruleset
const maxPFRetries = 10

// addPFNATRules configures PF to masquerade traffic from Tailscale addresses
// leaving via non-Tailscale interfaces. This is the FreeBSD equivalent of the
// Linux iptables MASQUERADE rule used for subnet routing.
//
// Rules are loaded into the "tailscale" PF anchor so that any pre-existing
// user rules in the main ruleset are left untouched.
func (r *freebsdRouter) addPFNATRules() error {
	// Ensure the PF kernel module is loaded.
	cmd("kldload", "pf").CombinedOutput() // may already be loaded

	// Enable PF (idempotent; returns error if already enabled).
	cmd("pfctl", "-e").CombinedOutput()

	// Ensure the main ruleset references our anchor so PF evaluates it.
	// We add both a nat-anchor (for NAT rules) and an anchor (for filter
	// rules, currently just "pass" to avoid blocking) if not already present.
	if err := ensurePFAnchorRef(r.logf); err != nil {
		return fmt.Errorf("ensuring PF anchor reference: %w", err)
	}

	// Load rules into the tailscale anchor.
	// Traffic from Tailscale CGNAT (100.64.0.0/10) or ULA (fd7a:115c:a1e0::/48)
	// addresses exiting any non-Tailscale interface is source-NATed to the
	// outgoing interface's address so that return traffic routes back through
	// this node.
	rules := fmt.Sprintf(
		"nat on ! %s inet from 100.64.0.0/10 to any -> (self)\n"+
			"nat on ! %s inet6 from fd7a:115c:a1e0::/48 to any -> (self)\n",
		r.tunname, r.tunname,
	)

	pfctl := exec.Command("pfctl", "-a", pfAnchorName, "-f", "-")
	pfctl.Stdin = strings.NewReader(rules)
	out, err := pfctl.CombinedOutput()
	if err != nil {
		return fmt.Errorf("pfctl -a %s -f: %v (%s)", pfAnchorName, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// getPFMainRuleset reads the current main PF filter and NAT rules.
func getPFMainRuleset() (scrubRules, natRules, filterRules string) {
	if out, err := cmd("pfctl", "-s", "nat").CombinedOutput(); err == nil {
		natRules = string(out)
	}
	if out, err := cmd("pfctl", "-s", "rules").CombinedOutput(); err == nil {
		var scrubLines, filterLines strings.Builder
		for filterLine := range strings.Lines(string(out)) {
			if strings.HasPrefix(filterLine, "scrub") {
				scrubLines.WriteString(filterLine)
			} else {
				filterLines.WriteString(filterLine)
			}
		}

		scrubRules = scrubLines.String()
		filterRules = filterLines.String()
	}
	return
}

// rulesetReferencesTables reports whether rules mention any pf table, e.g.
// "<zabbix_proxies>". "pfctl -s rules" prints table names but never their
// contents, so reloading such a ruleset without preserving table contents would
// redefine those tables as empty and silently stop the rules matching.
func rulesetReferencesTables(rules string) bool {
	for _, line := range strings.Split(rules, "\n") {
		if i := strings.IndexByte(line, '<'); i >= 0 && strings.IndexByte(line[i:], '>') > 0 {
			return true
		}
	}
	return false
}

// loadPFMainRuleset replaces the main PF ruleset with the given combined
// NAT + filter rules.
//
// Reloading the main ruleset is inherently lossy: we reconstruct it from
// "pfctl -s" output, which prints table names but never their contents, so any
// table the ruleset references comes back empty. pfctl's "-T load" looks like it
// would avoid this, but that command has never been implemented in FreeBSD's pf
// (nor OpenBSD's) -- see FreeBSD bug 291318. Before FreeBSD 15.0 pfctl silently
// ignored it; 15.0 tightened argument checking and rejects it outright. Either
// way it preserves nothing, so we do not pass it.
//
// Because we cannot reload safely, refuse when the existing ruleset references
// tables and tell the operator to declare the anchors statically in pf.conf,
// where they survive reloads and tailscaled never has to touch the main ruleset.
func loadPFMainRuleset(logf logger.Logf, rules string) error {
	if rulesetReferencesTables(rules) {
		return fmt.Errorf("refusing to reload the main PF ruleset: it references pf tables whose contents cannot be preserved across a reload; "+
			"add 'nat-anchor \"%s\"' and 'anchor \"%s\"' to pf.conf instead", pfAnchorName, pfAnchorName)
	}
	bo := backoff.NewBackoff("pfctl", logf, 2*time.Second)
	var retries int
	for {
		pfctl := exec.Command("pfctl", "-N", "-R", "-f", "-")
		pfctl.Stdin = strings.NewReader(rules)
		out_bytes, err := pfctl.CombinedOutput()
		out := string(out_bytes)
		if err == nil {
			break
		}
		if strings.Contains(out, "Device busy") && retries < maxPFRetries {
			// Retry if /dev/pf ioctl returns EBUSY, usually due to concurrent access
			bo.BackOff(context.Background(), err)
			retries++
			continue
		}
		return fmt.Errorf("pfctl -N -R -f: %v (%s)", err, strings.TrimSpace(out))
	}
	return nil
}

// ensurePFAnchorRef makes sure the main PF ruleset contains nat-anchor and
// anchor references for "tailscale". Without these, PF won't evaluate our
// anchor even if it has rules loaded.
//
// We read the current main ruleset and prepend the references only if they're
// not already present, then reload the combined ruleset.
func ensurePFAnchorRef(logf logger.Logf) error {
	scrubRules, natRules, filterRules := getPFMainRuleset()

	natAnchorRef := fmt.Sprintf("nat-anchor \"%s\"", pfAnchorName)
	filterAnchorRef := fmt.Sprintf("anchor \"%s\"", pfAnchorName)

	newNat := natRules
	newFilter := filterRules

	// Prepend our anchor references so they're evaluated, then include
	// all existing rules so we don't disrupt the user's configuration.
	if !strings.Contains(natRules, natAnchorRef) {
		newNat = natAnchorRef + "\n" + natRules
	}
	if !strings.Contains(filterRules, filterAnchorRef) {
		newFilter = filterAnchorRef + "\n" + filterRules
	}
	if newNat == natRules && newFilter == filterRules {
		return nil // already present
	}

	err := loadPFMainRuleset(logf, scrubRules+newNat+newFilter)
	if err == nil {
		shouldCleanupPfAnchors.Store(true)
		logf("added PF anchors to main ruleset")
	}
	return err
}

// removePFAnchorRef removes the nat-anchor and anchor references for
// "tailscale" from the main PF ruleset via read-modify-write, leaving
// all other rules intact.
func removePFAnchorRef(logf logger.Logf) error {
	scrubRules, natRules, filterRules := getPFMainRuleset()

	natAnchorRef := fmt.Sprintf("nat-anchor \"%s\"", pfAnchorName)
	filterAnchorRef := fmt.Sprintf("anchor \"%s\"", pfAnchorName)

	newNat := removeLines(natRules, natAnchorRef)
	newFilter := removeLines(filterRules, filterAnchorRef)

	if newNat == natRules && newFilter == filterRules {
		return nil // nothing to remove
	}

	return loadPFMainRuleset(logf, scrubRules+newNat+newFilter)
}

// removeLines removes all lines from s that contain substr.
func removeLines(s, substr string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(s, "\n") {
		if strings.Contains(line, substr) {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// delPFNATRules flushes rules inside the tailscale PF anchor and removes
// the anchor references from the main ruleset.
func (r *freebsdRouter) delPFNATRules() error {
	// Flush rules inside the anchor.
	if out, err := cmd("pfctl", "-a", pfAnchorName, "-F", "all").CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl -a %s -F all: %v (%s)", pfAnchorName, err, strings.TrimSpace(string(out)))
	}

	if shouldCleanupPfAnchors.CompareAndSwap(true, false) {
		// Remove the anchor references from the main ruleset.
		if err := removePFAnchorRef(r.logf); err != nil {
			return fmt.Errorf("removing PF anchor reference: %w", err)
		}
		r.logf("removed PF anchors from main ruleset")
	}
	return nil
}

func (r *freebsdRouter) Close() error {
	cleanUp(r.logf, r.tunname)
	return nil
}

func cleanUp(logf logger.Logf, interfaceName string) {
	// Flush only the tailscale PF anchor, leaving user rules intact.
	if out, err := cmd("pfctl", "-a", pfAnchorName, "-F", "all").CombinedOutput(); err != nil {
		logf("pfctl flush anchor %s: %v (%s)", pfAnchorName, err, strings.TrimSpace(string(out)))
	}
	if shouldCleanupPfAnchors.CompareAndSwap(true, false) {
		// Remove the anchor references from the main ruleset.
		if err := removePFAnchorRef(logf); err != nil {
			logf("removing PF anchor ref: %v", err)
		}
	}

	// If the interface was left behind, ifconfig down will not remove it.
	// In fact, this will leave a system in a tainted state where starting tailscaled
	// will result in "interface tailscale0 already exists"
	// until the defunct interface is ifconfig-destroyed.
	if out, err := cmd("ifconfig", interfaceName, "destroy").CombinedOutput(); err != nil {
		logf("ifconfig destroy: %v\n%s", err, out)
	}
}
