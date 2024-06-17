// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"cmp"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
)

// EndpointProvider is an enum that represents the source of an Endpoint.
type EndpointProvider int

const (
	// DERPMapPreferred is used for an endpoint that is a DERP node contained in the current preferred DERP region,
	// as provided by the DERPMap.
	DERPMapPreferred EndpointProvider = iota
	// Tailscale is used for endpoints that are the Tailscale coordination server or admin console.
	Tailscale
	// Platform is used for an endpoint that is a well-known captive portal detection URL for the current platform
	// (operated by Apple, Microsoft, etc.)
	Platform
	// DERPMapOther is used for an endpoint that is a DERP node, but not contained in the current preferred DERP region.
	DERPMapOther
)

func (p EndpointProvider) String() string {
	switch p {
	case DERPMapPreferred:
		return "DERPMapPreferred"
	case Tailscale:
		return "Tailscale"
	case Platform:
		return "Platform"
	case DERPMapOther:
		return "DERPMapOther"
	default:
		return fmt.Sprintf("EndpointProvider(%d)", p)
	}
}

// Endpoint represents a URL that can be used to detect a captive portal, along with the expected
// result of the HTTP request.
type Endpoint struct {
	// URL is the URL that we make an HTTP request to as part of the captive portal detection process.
	URL string
	// StatusCode is the expected HTTP status code that we expect to see in the response.
	StatusCode int
	// ExpectedContent is a string that we expect to see contained in the response body. If this is non-empty,
	// we will check that the response body contains this string. If it is empty, we will not check the response body
	// and only check the status code.
	ExpectedContent string
	// SupportsTailscaleChallenge is true if the endpoint will return the sent value of the X-Tailscale-Challenge
	// HTTP header in its HTTP response.
	SupportsTailscaleChallenge bool
	// Provider is the source of the endpoint. This is used to prioritize certain endpoints over others
	// (for example, a DERP node in the preferred region should always be used first).
	Provider EndpointProvider
}

func (e Endpoint) String() string {
	return fmt.Sprintf("Endpoint{URL=%q, StatusCode=%d, ExpectedContent=%q, SupportsTailscaleChallenge=%v, Provider=%s}", e.URL, e.StatusCode, e.ExpectedContent, e.SupportsTailscaleChallenge, e.Provider.String())
}

// availableEndpoints returns a set of Endpoints which can be used for captive portal detection by performing
// one or more HTTP requests and looking at the response. The returned Endpoints are ordered by preference,
// with the most preferred Endpoint being the first in the slice.
func availableEndpoints(derpMap *tailcfg.DERPMap, preferredDERPRegionID int, logf logger.Logf, goos string) []Endpoint {
	if logf == nil {
		logf = log.Printf
	}

	endpoints := []Endpoint{}

	if derpMap != nil {
		// If we have a DERP map, we can use the DERP hostnames and IPs as captive portal detection endpoints.
		for _, region := range derpMap.Regions {
			if region.Avoid {
				continue
			}
			for _, node := range region.Nodes {
				if node.IPv4 == "" {
					continue
				}
				url := "http://" + node.IPv4 + "/generate_204"
				p := DERPMapOther
				if region.RegionID == preferredDERPRegionID {
					p = DERPMapPreferred
				}
				e := Endpoint{url, http.StatusNoContent, "", true, p}
				endpoints = append(endpoints, e)
			}
		}
	} else {
		logf("[v2] captivedetection: DERP map is nil, skipping DERP endpoints for captive portal detection")
	}

	// Let's also try the default Tailscale coordination server and admin console.
	// These are likely to be blocked on some networks.
	cs := Endpoint{"http://controlplane.tailscale.com/generate_204", http.StatusNoContent, "", false, Tailscale}
	ac := Endpoint{"http://login.tailscale.com/generate_204", http.StatusNoContent, "", false, Tailscale}
	endpoints = append(endpoints, cs, ac)

	// Lastly, to be safe, let's also include some well-known captive portal detection URLs that are not under the
	// tailscale.com umbrella. These are less likely to be blocked on public networks since blocking them
	// would break captive portal detection for many devices.
	switch goos {
	case "windows":
		endpoints = append(endpoints, Endpoint{"http://www.msftconnecttest.com/connecttest.txt", http.StatusOK, "Microsoft Connect Test", false, Platform})
		endpoints = append(endpoints, Endpoint{"http://www.msftncsi.com/ncsi.txt", http.StatusOK, "Microsoft NCSI", false, Platform})
	case "darwin", "ios":
		endpoints = append(endpoints, Endpoint{"http://captive.apple.com/hotspot-detect.html", http.StatusOK, "Success", false, Platform})
		endpoints = append(endpoints, Endpoint{"http://www.thinkdifferent.us/", http.StatusOK, "Success", false, Platform})
		endpoints = append(endpoints, Endpoint{"http://www.airport.us/", http.StatusOK, "Success", false, Platform})
	case "android":
		endpoints = append(endpoints, Endpoint{"http://connectivitycheck.android.com/generate_204", http.StatusNoContent, "", false, Platform})
		endpoints = append(endpoints, Endpoint{"http://connectivitycheck.gstatic.com/generate_204", http.StatusNoContent, "", false, Platform})
		endpoints = append(endpoints, Endpoint{"http://play.googleapis.com/generate_204", http.StatusNoContent, "", false, Platform})
		endpoints = append(endpoints, Endpoint{"http://clients3.google.com/generate_204", http.StatusNoContent, "", false, Platform})
	default:
		endpoints = append(endpoints, Endpoint{"http://detectportal.firefox.com/success.txt", http.StatusOK, "success", false, Platform})
		endpoints = append(endpoints, Endpoint{"http://network-test.debian.org/nm", http.StatusOK, "NetworkManager is online", false, Platform})
	}

	// Sort the endpoints by provider so that we can prioritize DERP nodes in the preferred region, followed by
	// Tailscale endpoints, followed by platform-specific endpoints, then DERP nodes in any other region.
	slices.SortFunc(endpoints, func(x, y Endpoint) int {
		return cmp.Compare(x.Provider, y.Provider)
	})

	return endpoints
}

// responseLooksLikeCaptive checks if the given HTTP response matches the expected response for the Endpoint.
func (e Endpoint) responseLooksLikeCaptive(r *http.Response, logf logger.Logf) bool {
	defer r.Body.Close()

	// Check the status code first.
	if r.StatusCode != e.StatusCode {
		logf("[v1] unexpected status code in captive portal response: want=%d, got=%d", e.StatusCode, r.StatusCode)
		return true
	}

	// If the endpoint supports the Tailscale challenge header, check that the response contains the expected header.
	if e.SupportsTailscaleChallenge {
		if u, err := url.Parse(e.URL); err == nil {
			expectedResponse := "response ts_" + u.Host
			hasResponse := r.Header.Get("X-Tailscale-Response") == expectedResponse
			if !hasResponse {
				// The response did not contain the expected X-Tailscale-Response header, which means we are most likely
				// behind a captive portal (somebody is tampering with the response headers).
				logf("captive portal check response did not contain expected X-Tailscale-Response header: want=%q, got=%q", expectedResponse, r.Header.Get("X-Tailscale-Response"))
				return true
			}
		}
	}

	// If we don't have an expected content string, we don't need to check the response body.
	if e.ExpectedContent == "" {
		return false
	}

	// Read the response body and check if it contains the expected content.
	b, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		logf("reading captive portal check response body failed: %v", err)
		return false
	}
	hasExpectedContent := strings.Contains(string(b), e.ExpectedContent)
	if !hasExpectedContent {
		// The response body did not contain the expected content, that means we are most likely behind a captive portal.
		logf("[v1] captive portal check response body did not contain expected content: want=%q", e.ExpectedContent)
		return true
	}

	// If we got here, the response looks good.
	return false
}
