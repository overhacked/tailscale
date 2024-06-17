// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !(ios || darwin)

package captivedetection

import (
	"syscall"

	"tailscale.com/types/logger"
)

func prepareRawConn(c syscall.RawConn, ifIndex int, logf logger.Logf) error {
	// No-op on most platforms.
	return nil
}
