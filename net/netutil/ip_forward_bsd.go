// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package netutil

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
)

func ipForwardingEnabled(p protocol, iface string) (bool, error) {
	k := ipForwardSysctlKey(dotFormat, p, iface)
	bs, err := exec.Command("sysctl", "-n", k).Output()
	if err != nil {
		return false, fmt.Errorf("couldn't check %s (%v)", k, err)
	}

	val, err := strconv.ParseInt(string(bytes.TrimSpace(bs)), 10, 32)
	if err != nil {
		return false, fmt.Errorf("couldn't parse %s (%v)", k, err)
	}
	if val < 0 || val > 1 {
		return false, fmt.Errorf("unexpected value %d for %s", val, k)
	}
	on := val == 1
	return on, nil
}

func reversePathFilterValue(_ string) (int, error) {
	return 0, nil
}

func ipForwardSysctlKey(format sysctlFormat, p protocol, _ string) string {
	if format != dotFormat {
		panic("unexpected: format != dotFormat in BSD implementation")
	}
	if p == ipv4 {
		return "net.inet.ip.forwarding"
	} else {
		return "net.inet6.ip6.forwarding"
	}
}
