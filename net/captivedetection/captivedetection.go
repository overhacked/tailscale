// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package captivedetection provides a way to detect if the system is connected to a network that has
// a captive portal. It does this by making HTTP requests to known captive portal detection endpoints
// and checking if the HTTP responses indicate that a captive portal might be present.
package captivedetection

import (
	"context"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// Detective is a type used to detect if the system is behind a captive portal.
type Detector struct {
	// mu is the mutex used to ensure that only one captive portal detection attempt is running at a time.
	mu sync.Mutex
	// httpClient is the HTTP client that is used for captive portal detection. It is configured to not follow redirects
	// and to have a short timeout since it will talk to a LAN device.
	httpClient *http.Client
}

func NewDetector() *Detector {
	return &Detector{
		httpClient: &http.Client{
			// No redirects allowed
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: http.DefaultClient.Transport,
			Jar:       http.DefaultClient.Jar,
			Timeout:   Timeout,
		},
	}
}

// Timeout is the timeout for captive portal detection requests. Because the captive portal intercepting our requests
// is usually located on the LAN, this is a very short timeout.
const Timeout time.Duration = 500 * time.Millisecond

// DetectCaptivePortal is the entry point to the API. It attempts to detect if the system is behind a captive portal
// by making HTTP requests to known captive portal detection Endpoints. If any of the requests return a response code
// or body that looks like a captive portal, we return true. We return false in all other cases, including when any
// error occurs during a detection attempt.
//
// This function might take a while to return, as it will attempt to detect a captive portal on all available interfaces
// by performing multiple HTTP requests. It should be called in a separate goroutine if you want to avoid blocking.
func (d *Detector) DetectCaptivePortal(ifst *netmon.State, derpMap *tailcfg.DERPMap, preferredDERPRegionID int, logf logger.Logf) (found bool) {
	return d.detectCaptivePortalWithGOOS(ifst, derpMap, preferredDERPRegionID, logf, runtime.GOOS)
}

func (d *Detector) detectCaptivePortalWithGOOS(ifst *netmon.State, derpMap *tailcfg.DERPMap, preferredDERPRegionID int, logf logger.Logf, goos string) (found bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if logf == nil {
		logf = log.Printf
	}

	if !ifst.AnyInterfaceUp() {
		logf("DetectCaptivePortal: no interfaces up, returning false")
		return false
	}

	endpoints := availableEndpoints(derpMap, preferredDERPRegionID, logf, goos)

	// Here we try detecting a captive portal using *all* available interfaces on the system
	// that have a IPv4 address. We consider to have found a captive portal when any interface
	// reports one may exists. This is necessary because most systems have multiple interfaces,
	// and most importantly on macOS no default route interface is set until the user has accepted
	// the captive portal alert thrown by the system. If no default route interface is known,
	// we need to try with anything that might remotely resemble a Wi-Fi interface.
	for ifName, i := range ifst.Interface {
		if !i.IsUp() || i.IsLoopback() || interfaceNameDoesNotNeedCaptiveDetection(ifName, goos) {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			logf("[v1] DetectCaptivePortal: failed to get addresses for interface %s: %v", ifName, err)
			continue
		}
		if len(addrs) == 0 {
			continue
		}
		logf("[v2] attempting to do captive portal detection on interface %s", ifName)
		res := d.detectOnInterface(i.Index, endpoints, logf)
		if res {
			logf("DetectCaptivePortal(found=true,ifName=%s)", found, ifName)
			return true
		}
	}

	logf("DetectCaptivePortal(found=false)")
	return false
}

func interfaceNameDoesNotNeedCaptiveDetection(ifName string, goos string) bool {
	ifName = strings.ToLower(ifName)
	excludedPrefixes := []string{"tailscale", "tun", "tap", "docker", "kube", "wg"}
	if goos == "windows" {
		excludedPrefixes = append(excludedPrefixes, "loopback", "tunnel", "ppp", "isatap", "teredo", "6to4")
	} else if goos == "darwin" || goos == "ios" {
		excludedPrefixes = append(excludedPrefixes, "awdl", "bridge", "ap", "utun", "tap", "llw", "anpi", "lo", "stf", "gif", "xhc")
	}
	for _, prefix := range excludedPrefixes {
		if strings.HasPrefix(ifName, prefix) {
			return true
		}
	}
	return false
}

// detectOnInterface reports whether or not we think the system is behind a
// captive portal, detected by making a request to a URL that we know should
// return a "204 No Content" response and checking if that's what we get.
//
// The boolean return is whether we think we have a captive portal.
func (d *Detector) detectOnInterface(ifIndex int, endpoints []Endpoint, logf logger.Logf) bool {
	defer d.httpClient.CloseIdleConnections()

	logf("[v2] %d available captive portal detection endpoints: %v", len(endpoints), endpoints)

	for i, e := range endpoints {
		if i >= 3 {
			// Try a maximum of 3 endpoints, break out (returning false) if we run of attempts.
			break
		}

		found, err := d.verifyCaptivePortalEndpoint(e, ifIndex, logf)
		if err != nil {
			logf("[v1] checkCaptivePortalEndpoint failed with endpoint %v: %v", e, err)
			continue
		}

		if found {
			return true
		}
	}
	return false
}

// verifyCaptivePortalEndpoint checks if the given Endpoint is a captive portal by making an HTTP request to the
// given Endpoint URL using the interface with index ifIndex, and checking if the response looks like a captive portal.
func (d *Detector) verifyCaptivePortalEndpoint(e Endpoint, ifIndex int, logf logger.Logf) (found bool, err error) {
	req, err := http.NewRequest("GET", e.URL, nil)
	if err != nil {
		return false, err
	}

	// Attach the Tailscale challenge header if the endpoint supports it. Not all captive portal detection endpoints
	// support this, so we only attach it if the endpoint does.
	if e.SupportsTailscaleChallenge {
		if u, err := url.Parse(e.URL); err == nil {
			// Note: the set of valid characters in a challenge and the total
			// length is limited; see isChallengeChar in cmd/derper for more
			// details.
			chal := "ts_" + u.Host
			req.Header.Set("X-Tailscale-Challenge", chal)
		}
	}

	// Force the HTTP connection to use the given interface.
	// Why? On Darwin, until you've accepted or closed the macOS captive portal alert,
	// no default route interface is available, so all requests will fail unless we do this.
	// TODO: investigate if this is also necessary on other platforms (Windows?)
	dl := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return prepareRawConn(c, ifIndex, logf)
		},
	}
	d.httpClient.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dl.Dial(network, addr)
		},
	}

	// Make the actual request, and check if the response looks like a captive portal or not.
	r, err := d.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	return e.responseLooksLikeCaptive(r, logf), nil
}
