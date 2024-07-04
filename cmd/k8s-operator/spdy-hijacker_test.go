// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"go.uber.org/zap"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstest"
)

func Test_SPDYHijacker(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name                        string
		failOpen                    bool
		failRecorderConnect         bool // fail initial connect to the recorder
		failRecorderConnPostConnect bool // send error down the error channel
		wantsConnClosed             bool
		wantsSetupErr               bool
	}{
		{
			name: "setup succeeds, conn stays open",
		},
		{
			name:                "setup fails, policy is to fail open, conn stays open",
			failOpen:            true,
			failRecorderConnect: true,
		},
		{
			name:                "setup fails, policy is to fail closed, conn is closed",
			failRecorderConnect: true,
			wantsSetupErr:       true,
			wantsConnClosed:     true,
		},
		{
			name:                        "connection fails post-initial connect, policy is to fail open, conn stays open",
			failRecorderConnPostConnect: true,
			failOpen:                    true,
		},
		{
			name:                        "connection fails post-initial connect, policy is to fail closed, conn is closed",
			failRecorderConnPostConnect: true,
			wantsConnClosed:             true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &testConn{}
			ch := make(chan error)
			h := &spdyHijacker{
				connectToRecorder: func(context.Context, []netip.AddrPort, *tsdial.Dialer) (wc io.WriteCloser, rec []*tailcfg.SSHRecordingAttempt, _ <-chan error, err error) {
					if tt.failRecorderConnect {
						err = errors.New("test")
					}
					return wc, rec, ch, err
				},
				failOpen: tt.failOpen,
				who:      &apitype.WhoIsResponse{Node: &tailcfg.Node{}, UserProfile: &tailcfg.UserProfile{}},
				log:      zl.Sugar(),
				ts:       &tsnet.Server{},
				req:      &http.Request{URL: &url.URL{}},
			}
			ctx := context.Background()
			_, err := h.setUpRecording(ctx, tc)
			if (err != nil) != tt.wantsSetupErr {
				t.Errorf("spdyHijacker.setupRecording() error = %v, wantErr %v", err, tt.wantsSetupErr)
				return
			}
			if tt.failRecorderConnPostConnect {
				select {
				case ch <- errors.New("err"):
				case <-time.After(time.Second * 15):
					t.Errorf("error from recorder conn was not read within 15 seconds")
				}
			}
			timeout := time.Second * 20
			// TODO (irbekrm): cover case where an error is received
			// over channel and the failure policy is to fail open
			// (test that connection remains open over some period
			// of time).
			if err := tstest.WaitFor(timeout, func() (err error) {
				if tt.wantsConnClosed != tc.isClosed() {
					return fmt.Errorf("got connection state: %t, wants connection state: %t", tc.closed, tt.wantsConnClosed)
				}
				return nil
			}); err != nil {
				t.Errorf("connection did not reach the desired state within %s", timeout.String())
			}
			ctx.Done()
		})
	}
}
