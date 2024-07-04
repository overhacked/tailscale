// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/net/tsdial"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstime"
	"tailscale.com/util/multierr"
)

// spdyHijacker implements [net/http.Hijacker] interface.
// It must be configured with an http request for a 'kubectl exec' session that
// needs to be recorded. It knows how to hijack the connection and configure for
// the session contents to be sent to a tsrecorder instance.
type spdyHijacker struct {
	http.ResponseWriter
	ts                *tsnet.Server
	req               *http.Request
	who               *apitype.WhoIsResponse
	log               *zap.SugaredLogger
	pod               string           // pod being exec-d
	ns                string           // namespace of the pod being exec-d
	addrs             []netip.AddrPort // tsrecorder addresses
	failOpen          bool             // whether to fail open if recording fails
	connectToRecorder func(context.Context, []netip.AddrPort, *tsdial.Dialer) (io.WriteCloser, []*tailcfg.SSHRecordingAttempt, <-chan error, error)
}

// Hijack hijacks a 'kubectl exec' session and configures for the session
// contents to be sent to a recorder.
func (h *spdyHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.log.Infof("recorder addrs: %v, failOpen: %v", h.addrs, h.failOpen)
	reqConn, brw, err := h.ResponseWriter.(http.Hijacker).Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("error hijacking connection: %w", err)
	}

	conn, err := h.setUpRecording(context.Background(), reqConn)
	if err != nil {
		return nil, nil, fmt.Errorf("error setting up session recording: %w", err)
	}
	return conn, brw, nil
}

// setupRecording attempts to connect to the recorders set via
// spdyHijacker.addrs. Returns conn from provided opts, wrapped in recording
// logic. If connecting to the recorder fails or an error is received during the
// session and spdyHijacker.failOpen is false, connection will be closed.
func (h *spdyHijacker) setUpRecording(ctx context.Context, conn net.Conn) (net.Conn, error) {
	const (
		// https://docs.asciinema.org/manual/asciicast/v2/
		asciicastv2 = 2
	)
	var wc io.WriteCloser
	h.log.Infof("kubectl exec session will be recorded, recorders: %v, fail open policy: %t", h.addrs, h.failOpen)
	// TODO (irbekrm): send client a message that session will be recorded.
	rw, _, errChan, err := h.connectToRecorder(ctx, h.addrs, h.ts.Dialer())
	if err != nil {
		msg := fmt.Sprintf("error connecting to session recorders: %v", err)
		if h.failOpen {
			msg = msg + "; failure mode is 'fail open'; continuing session without recording."
			h.log.Warnf(msg)
			return conn, nil
		}
		msg = msg + "; failure mode is 'fail closed'; closing connection."
		if err := closeConnWithWarning(conn, msg); err != nil {
			return nil, multierr.New(errors.New(msg), err)
		}
		return nil, errors.New(msg)
	}

	// TODO (irbekrm): log which recorder
	h.log.Info("successfully connected to a session recorder")
	wc = rw
	cl := tstime.DefaultClock{}
	lc := &spdyRemoteConnRecorder{
		log:  h.log,
		Conn: conn,
		rec: &recorder{
			start:    cl.Now(),
			clock:    cl,
			failOpen: h.failOpen,
			conn:     wc,
		},
	}

	qp := h.req.URL.Query()
	ch := CastHeader{
		Version:   asciicastv2,
		Timestamp: lc.rec.start.Unix(),
		Command:   strings.Join(qp["command"], " "),
		SrcNode:   strings.TrimSuffix(h.who.Node.Name, "."),
		SrcNodeID: h.who.Node.StableID,
		Namespace: h.ns,
		Pod:       h.pod,
	}
	if !h.who.Node.IsTagged() {
		ch.SrcNodeUser = h.who.UserProfile.LoginName
		ch.SrcNodeUserID = h.who.Node.User
	} else {
		ch.SrcNodeTags = h.who.Node.Tags
	}
	lc.ch = ch
	go func() {
		var err error
		select {
		case <-ctx.Done():
			return
		case err = <-errChan:
		}
		if err == nil {
			h.log.Info("finished uploading the recording")
			return
		}
		msg := fmt.Sprintf("connection to the session recorder errorred: %v;", err)
		if h.failOpen {
			msg += msg + "; failure mode is 'fail open'; continuing session without recording."
			h.log.Info(msg)
			return
		}
		msg += "; failure mode set to 'fail closed'; closing connection"
		h.log.Error(msg)
		lc.failed = true
		// TODO (irbekrm): write a message to the client
		if err := lc.Close(); err != nil {
			h.log.Infof("error closing recorder connections: %v", err)
		}
		return
	}()
	return lc, nil
}

// CastHeader is the asciicast header to be sent to the recorder at the start of
// the recording of a session.
// https://docs.asciinema.org/manual/asciicast/v2/#header
type CastHeader struct {
	// Version is the asciinema file format version.
	Version int `json:"version"`

	// Width is the terminal width in characters.
	Width int `json:"width"`

	// Height is the terminal height in characters.
	Height int `json:"height"`

	// Timestamp is the unix timestamp of when the recording started.
	Timestamp int64 `json:"timestamp"`

	// Tailscale-specific fields: SrcNode is the full MagicDNS name of the
	// tailnet node originating the connection, without the trailing dot.
	SrcNode string `json:"srcNode"`

	// SrcNodeID is the node ID of the tailnet node originating the connection.
	SrcNodeID tailcfg.StableNodeID `json:"srcNodeID"`

	// SrcNodeTags is the list of tags on the node originating the connection (if any).
	SrcNodeTags []string `json:"srcNodeTags,omitempty"`

	// SrcNodeUserID is the user ID of the node originating the connection (if not tagged).
	SrcNodeUserID tailcfg.UserID `json:"srcNodeUserID,omitempty"` // if not tagged

	// SrcNodeUser is the LoginName of the node originating the connection (if not tagged).
	SrcNodeUser string `json:"srcNodeUser,omitempty"`

	// Kubernetes-specific fields:
	// Namespace of the Pod that is being exec-ed to.
	Namespace string `json:"namespace,omitempty"`
	// Name of the Pod that is being exec-ed to.
	Pod     string `json:"pod,omitempty"`
	Command string
}

func closeConnWithWarning(conn net.Conn, msg string) error {
	b := io.NopCloser(bytes.NewBuffer([]byte(msg)))
	resp := http.Response{Status: http.StatusText(http.StatusForbidden), StatusCode: http.StatusForbidden, Body: b}
	if err := resp.Write(conn); err != nil {
		return multierr.New(fmt.Errorf("error writing msg %q to conn: %v", msg, err), conn.Close())
	}
	return conn.Close()
}
