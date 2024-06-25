// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"bytes"
	"encoding/json"
	"net"
	"reflect"
	"testing"

	"go.uber.org/zap"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
)

// Test_Writes tests that 1 or more Write calls to spdyRemoteConnRecorder
// results in the expected data being forwarded to the original destination and
// the session recorder.
func Test_Writes(t *testing.T) {
	var stdoutStreamID, stderrStreamID uint32 = 1, 2
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	tests := []struct {
		name          string
		inputs        [][]byte
		wantForwarded []byte
		wantRecorded  []byte
	}{
		{
			name:          "single_write_control_frame_with_payload",
			inputs:        [][]byte{{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x5}},
			wantForwarded: []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x5},
		},
		{
			name:          "two_writes_control_frame_with_leftover",
			inputs:        [][]byte{{0x80, 0x3, 0x0, 0x1}, {0x0, 0x0, 0x0, 0x1, 0x5, 0x80, 0x3}},
			wantForwarded: []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x5},
		},
		{
			name:          "single_write_stdout_data_frame",
			inputs:        [][]byte{{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0}},
			wantForwarded: []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0},
		},
		{
			name:          "single_write_stdout_data_frame_with_payload",
			inputs:        [][]byte{{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded: []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
			wantRecorded:  castLine(t, []byte{0x1, 0x2, 0x3, 0x4, 0x5}, cl),
		},
		{
			name:          "single_write_stderr_data_frame_with_payload",
			inputs:        [][]byte{{0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded: []byte{0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
			wantRecorded:  castLine(t, []byte{0x1, 0x2, 0x3, 0x4, 0x5}, cl),
		},
		{
			name:          "single_data_frame_unknow_stream_with_payload",
			inputs:        [][]byte{{0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded: []byte{0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
		},
		{
			name:          "control_frame_and_data_frame_split_across_two_writes",
			inputs:        [][]byte{{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, {0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded: []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
			wantRecorded:  castLine(t, []byte{0x1, 0x2, 0x3, 0x4, 0x5}, cl),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &testConn{}
			sr := &testSessionRecorder{}
			lw := &loggingWriter{
				sessionRecorder: sr,
				clock:           cl,
				start:           cl.Now(),
				log:             zl.Sugar(),
			}

			c := &spdyRemoteConnRecorder{
				Conn: tc,
				log:  zl.Sugar(),
				lw:   lw,
			}

			c.stdoutStreamID.Store(stdoutStreamID)
			c.stderrStreamID.Store(stderrStreamID)
			for i, input := range tt.inputs {
				if _, err := c.Write(input); err != nil {
					t.Errorf("[%d] spdyRemoteConnRecorder.Write() unexpected error %v", i, err)
				}
			}

			// Assert that the expected bytes have been forwarded to the original destination.
			gotForwarded := tc.writeBuf.Bytes()
			if !reflect.DeepEqual(gotForwarded, tt.wantForwarded) {
				t.Errorf("expected bytes not forwarded, wants\n%v\ngot\n%v", tt.wantForwarded, gotForwarded)
			}

			// Assert that the expected bytes have been forwarded to the session recorder.
			gotRecorded := sr.buf.Bytes()
			if !reflect.DeepEqual(gotRecorded, tt.wantRecorded) {
				t.Errorf("expected bytes not recorded, wants\n%v\ngot\n%v", tt.wantRecorded, gotRecorded)
			}
		})
	}
}

// Test_Reads tests that 1 or more Read calls to spdyRemoteConnRecorder results
// in the expected data being forwarded to the original destination and the
// session recorder.
func Test_Reads(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	var reader zlibReader
	resizeMsg := resizeMsgBytes(t, 10, 20)
	synStreamStdoutPayload := payload(t, map[string]string{"Streamtype": "stdout"}, SYN_STREAM, 1)
	synStreamStderrPayload := payload(t, map[string]string{"Streamtype": "stderr"}, SYN_STREAM, 2)
	synStreamResizePayload := payload(t, map[string]string{"Streamtype": "resize"}, SYN_STREAM, 3)
	syn_stream_ctrl_header := []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, uint8(len(synStreamStdoutPayload))}

	tests := []struct {
		name                     string
		inputs                   [][]byte
		wantRecorded             []byte
		wantStdoutStreamID       uint32
		wantStderrStreamID       uint32
		wantResizeStreamID       uint32
		resizeStreamIDBeforeRead uint32
	}{
		{
			name:                     "resize_data_frame_single_read",
			inputs:                   [][]byte{append([]byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, uint8(len(resizeMsg))}, resizeMsg...)},
			resizeStreamIDBeforeRead: 1,
			wantRecorded:             asciinemaResizeMsg(t, 10, 20),
		},
		{
			name:                     "resize_data_frame_two_reads",
			inputs:                   [][]byte{{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, uint8(len(resizeMsg))}, resizeMsg},
			resizeStreamIDBeforeRead: 1,
			wantRecorded:             asciinemaResizeMsg(t, 10, 20),
		},
		{
			name:               "syn_stream_ctrl_frame_stdout_single_read",
			inputs:             [][]byte{append(syn_stream_ctrl_header, synStreamStdoutPayload...)},
			wantStdoutStreamID: 1,
		},
		{
			name:               "syn_stream_ctrl_frame_stderr_single_read",
			inputs:             [][]byte{append(syn_stream_ctrl_header, synStreamStderrPayload...)},
			wantStderrStreamID: 2,
		},
		{
			name:               "syn_stream_ctrl_frame_resize_single_read",
			inputs:             [][]byte{append(syn_stream_ctrl_header, synStreamResizePayload...)},
			wantResizeStreamID: 3,
		},
		{
			name:               "syn_stream_ctrl_frame_resize_four_reads_with_leftover",
			inputs:             [][]byte{syn_stream_ctrl_header, append(synStreamResizePayload, syn_stream_ctrl_header...), append(synStreamStderrPayload, syn_stream_ctrl_header...), append(synStreamStdoutPayload, 0x0, 0x3)},
			wantStdoutStreamID: 1,
			wantStderrStreamID: 2,
			wantResizeStreamID: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &testConn{}
			sr := &testSessionRecorder{}
			lw := &loggingWriter{
				sessionRecorder: sr,
				clock:           cl,
				start:           cl.Now(),
				log:             zl.Sugar(),
			}
			c := &spdyRemoteConnRecorder{
				Conn: tc,
				log:  zl.Sugar(),
				lw:   lw,
			}
			c.resizeStreamID.Store(tt.resizeStreamIDBeforeRead)

			for i, input := range tt.inputs {
				c.zlibReqReader = reader
				tc.readBuf.Reset()
				_, err := tc.readBuf.Write(input)
				if err != nil {
					t.Fatalf("writing bytes to test conn: %v", err)
				}
				_, err = c.Read(make([]byte, len(input)))
				if err != nil {
					t.Errorf("[%d] spdyRemoteConnRecorder.Read() resulted in an unexpected error: %v", i, err)
				}
			}
			// Assert that the expected bytes have been forwarded to the session recorder.
			gotRecorded := sr.buf.Bytes()
			if !reflect.DeepEqual(gotRecorded, tt.wantRecorded) {
				t.Errorf("expected bytes not recorded, wants\n%v\ngot\n%v", tt.wantRecorded, gotRecorded)
			}

			// Assert that the expected stream IDs have been stored.
			if id := c.resizeStreamID.Load(); id != tt.wantResizeStreamID && id != tt.resizeStreamIDBeforeRead {
				t.Errorf("wants resizeStreamID: %d, got %d", tt.wantResizeStreamID, id)
			}
			if id := c.stderrStreamID.Load(); id != tt.wantStderrStreamID {
				t.Errorf("wants stderrStreamID: %d, got %d", tt.wantStderrStreamID, id)
			}
			if id := c.stdoutStreamID.Load(); id != tt.wantStdoutStreamID {
				t.Errorf("wants stdoutStreamID: %d, got %d", tt.wantStdoutStreamID, id)
			}
		})
	}
}

func castLine(t *testing.T, p []byte, clock tstime.Clock) []byte {
	t.Helper()
	j, err := json.Marshal([]any{
		clock.Now().Sub(clock.Now()).Seconds(),
		"o",
		string(p),
	})
	if err != nil {
		t.Fatalf("error marshalling cast line: %v", err)
	}
	return append(j, '\n')
}

func resizeMsgBytes(t *testing.T, width, height int) []byte {
	t.Helper()
	bs, err := json.Marshal(spdyResizeMsg{Width: width, Height: height})
	if err != nil {
		t.Fatalf("error marshalling resizeMsg: %v", err)
	}
	return bs
}

func asciinemaResizeMsg(t *testing.T, width, height int) []byte {
	t.Helper()
	ch := CastHeader{
		Width:  width,
		Height: height,
	}
	bs, err := json.Marshal(ch)
	if err != nil {
		t.Fatalf("error marshalling CastHeader: %v", err)
	}
	return append(bs, '\n')
}

type testConn struct {
	net.Conn
	// writeBuf contains whatever was send to the conn via Write.
	writeBuf bytes.Buffer
	// readBuf contains whatever was sent to the conn via Read.
	readBuf bytes.Buffer
}

var _ net.Conn = &testConn{}

func (tc *testConn) Read(b []byte) (int, error) {
	return tc.readBuf.Read(b)
}

func (tc *testConn) Write(b []byte) (int, error) {
	return tc.writeBuf.Write(b)
}

type testSessionRecorder struct {
	// buf holds data that was sent to the session recorder.
	buf bytes.Buffer
}

func (t *testSessionRecorder) Write(b []byte) (int, error) {
	return t.buf.Write(b)
}

func (t *testSessionRecorder) Close() error {
	t.buf.Reset()
	return nil
}
