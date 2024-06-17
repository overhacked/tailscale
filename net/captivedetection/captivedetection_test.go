// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package captivedetection

import (
	"net/http"
	"runtime"
	"strings"
	"testing"

	"tailscale.com/net/netmon"
)

func TestAvailableEndpointsAlwaysAtLeastTwo(t *testing.T) {
	endpoints := availableEndpoints(nil, 0, nil, runtime.GOOS)
	if len(endpoints) == 0 {
		t.Errorf("Expected non-empty AvailableEndpoints, got an empty slice instead")
	}
	if len(endpoints) == 1 {
		t.Errorf("Expected at least two AvailableEndpoints for redundancy, got only one instead")
	}
	for _, e := range endpoints {
		if e.URL == "" {
			t.Errorf("Expected non-empty URL in Endpoint, got an empty string")
		}
		if strings.HasPrefix(e.URL, "https://") {
			t.Errorf("Expected HTTP URL in Endpoint, got HTTPS")
		}
	}
}

func TestAvailableEndpointsUsesAppleOnDarwin(t *testing.T) {
	darwinOK := false
	iosOK := false
	for _, os := range []string{"darwin", "ios"} {
		endpoints := availableEndpoints(nil, 0, nil, os)
		if len(endpoints) == 0 {
			t.Errorf("Expected non-empty AvailableEndpoints, got an empty slice instead")
		}
		want := Endpoint{"http://captive.apple.com/hotspot-detect.html", http.StatusOK, "Success", false, Platform}
		for _, e := range endpoints {
			if e == want {
				if os == "darwin" {
					darwinOK = true
				} else if os == "ios" {
					iosOK = true
				}
			}
		}
	}

	if !darwinOK || !iosOK {
		t.Errorf("Expected to find Apple captive portal detection URL on both Darwin and iOS, but didn't")
	}
}

func TestAvailableEndpointsUsesMSFTOnWindows(t *testing.T) {
	endpoints := availableEndpoints(nil, 0, nil, "windows")
	if len(endpoints) == 0 {
		t.Errorf("Expected non-empty AvailableEndpoints, got an empty slice instead")
	}
	want := Endpoint{"http://www.msftconnecttest.com/connecttest.txt", http.StatusOK, "Microsoft Connect Test", false, Platform}
	for _, e := range endpoints {
		if e == want {
			return
		}
	}
	t.Errorf("Expected to find Microsoft captive portal detection URL on Windows, but didn't")
}

func TestDetectCaptivePortalReturnsFalse(t *testing.T) {
	d := NewDetector()
	found := d.DetectCaptivePortal(netmon.NewStatic().InterfaceState(), nil, 0, nil)
	if found {
		t.Errorf("DetectCaptivePortal returned true, expected false. Are you actually behind a captive portal? If so, this test failure is expected.")
	}
}

func TestAllEndpointsAreUpAndReturnExpectedResponse(t *testing.T) {
	d := NewDetector()
	endpoints := availableEndpoints(nil, 0, nil, runtime.GOOS)
	for _, e := range endpoints {
		t.Logf("Testing endpoint %v", e)
		found, err := d.verifyCaptivePortalEndpoint(e, 0, nil)
		if err != nil {
			t.Errorf("verifyCaptivePortalEndpoint failed with endpoint %v: %v", e, err)
		}
		if found {
			t.Errorf("verifyCaptivePortalEndpoint with endpoint %v says we're behind a captive portal, but we aren't", e)
		}
	}
}
