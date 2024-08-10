// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package netutil

func ipForwardingEnabled(_ protocol, _ string) (bool, error) {
	return true, nil
}

func reversePathFilterValue(_ string) (int, error) {
	return 0, nil
}

func ipForwardSysctlKey(_ sysctlFormat, _ protocol, _ string) string {
	panic("should never be called on non-Linux, non-BSD platforms")
}
