// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package netutil

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// ipForwardingEnabled reports whether the IP Forwarding is enabled for the
// given interface.
// The iface param determines which interface to check against, "" means to check
// global config.
// This is Linux-specific: it only reads from /proc/sys and doesn't shell out to
// sysctl (which on Linux just reads from /proc/sys anyway).
func ipForwardingEnabled(p protocol, iface string) (bool, error) {
	k := ipForwardSysctlKey(slashFormat, p, iface)
	bs, err := os.ReadFile(filepath.Join("/proc/sys", k))
	if err != nil {
		if os.IsNotExist(err) {
			// If IPv6 is disabled, sysctl keys like "net.ipv6.conf.all.forwarding" just don't
			// exist on disk. But first diagnose whether procfs is even mounted before assuming
			// absence means false.
			if fi, err := os.Stat("/proc/sys"); err != nil {
				return false, fmt.Errorf("failed to check sysctl %v; no procfs? %w", k, err)
			} else if !fi.IsDir() {
				return false, fmt.Errorf("failed to check sysctl %v; /proc/sys isn't a directory, is %v", k, fi.Mode())
			}
			return false, nil
		}
		return false, err
	}

	val, err := strconv.ParseInt(string(bytes.TrimSpace(bs)), 10, 32)
	if err != nil {
		return false, fmt.Errorf("couldn't parse %s: %w", k, err)
	}
	// 0 = disabled, 1 = enabled, 2 = enabled (but uncommon)
	// https://github.com/tailscale/tailscale/issues/8375
	if val < 0 || val > 2 {
		return false, fmt.Errorf("unexpected value %d for %s", val, k)
	}
	on := val == 1 || val == 2
	return on, nil
}

// ipForwardSysctlKey returns the sysctl key for the given protocol and iface.
// When the dotFormat parameter is true the output is formatted as `net.ipv4.ip_forward`,
// else it is `net/ipv4/ip_forward`
func ipForwardSysctlKey(format sysctlFormat, p protocol, iface string) string {
	if iface == "" {
		if format == dotFormat {
			if p == ipv4 {
				return "net.ipv4.ip_forward"
			}
			return "net.ipv6.conf.all.forwarding"
		}
		if p == ipv4 {
			return "net/ipv4/ip_forward"
		}
		return "net/ipv6/conf/all/forwarding"
	}

	var k string
	if p == ipv4 {
		k = "net/ipv4/conf/%s/forwarding"
	} else {
		k = "net/ipv6/conf/%s/forwarding"
	}
	if format == dotFormat {
		// Swap the delimiters.
		iface = strings.ReplaceAll(iface, ".", "/")
		k = strings.ReplaceAll(k, "/", ".")
	}
	return fmt.Sprintf(k, iface)
}

// rpFilterSysctlKey returns the sysctl key for the given iface.
//
// Format controls whether the output is formatted as
// `net.ipv4.conf.iface.rp_filter` or `net/ipv4/conf/iface/rp_filter`.
func rpFilterSysctlKey(format sysctlFormat, iface string) string {
	// No iface means all interfaces
	if iface == "" {
		iface = "all"
	}

	k := "net/ipv4/conf/%s/rp_filter"
	if format == dotFormat {
		// Swap the delimiters.
		iface = strings.ReplaceAll(iface, ".", "/")
		k = strings.ReplaceAll(k, "/", ".")
	}
	return fmt.Sprintf(k, iface)
}

// reversePathFilterValue reports the reverse path filter setting on Linux
// for the given interface.
//
// The iface param determines which interface to check against; the empty
// string means to check the global config.
//
// This function tries to look up the value directly from `/proc/sys`, and
// falls back to using the `sysctl` command on failure.
func reversePathFilterValue(iface string) (int, error) {
	k := rpFilterSysctlKey(slashFormat, iface)
	bs, err := os.ReadFile(filepath.Join("/proc/sys", k))
	if err != nil {
		// Fall back to the sysctl command
		k := rpFilterSysctlKey(dotFormat, iface)
		bs, err = exec.Command("sysctl", "-n", k).Output()
		if err != nil {
			return -1, fmt.Errorf("couldn't check %s (%v)", k, err)
		}
	}
	v, err := strconv.Atoi(string(bytes.TrimSpace(bs)))
	if err != nil {
		return -1, fmt.Errorf("couldn't parse %s (%v)", k, err)
	}
	return v, nil
}
