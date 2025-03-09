// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package SSHFP implements the DNS RR type SSHFP and conversion of SSH host
// keys in known_hosts format to SSHFP resource records
package sshfp

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
	dns "golang.org/x/net/dns/dnsmessage"
)

// TypeSSHFP is a constant for SSHFP records, since net/dns does not declare it
const TypeSSHFP dns.Type = 44

// Algorithm of the host public key
type Algorithm uint8

const (
	AlgorithmReserved Algorithm = 0
	AlgorithmRSA      Algorithm = 1
	AlgorithmDSS      Algorithm = 2
	AlgorithmECDSA    Algorithm = 3
	AlgorithmEd25519  Algorithm = 4
)

// Type of the fingerprint checksum
type Type uint8

const (
	TypeReserved Type = 0
	TypeSHA1     Type = 1
	TypeSHA256   Type = 2
)

// SSHFP RR. See RFC 4255.
type SSHFP struct {
	Algorithm   Algorithm
	Type        Type
	FingerPrint []byte
}

func (l *SSHFP) Equals(r *SSHFP) bool {
	return l.Algorithm == r.Algorithm && l.Type == r.Type && slices.Equal(l.FingerPrint, r.FingerPrint)
}

func MarshalSSHFPResourceRecord(r SSHFP) ([]byte, error) {
	msg := make([]byte, len(r.FingerPrint)+2)

	msg[0] = byte(r.Algorithm)
	msg[1] = byte(r.Type)
	copy(msg[2:], r.FingerPrint)

	return msg, nil
}

func UnmarshalSSHPubKeyString(pk string) (SSHFP, error) {
	sshfp := SSHFP{}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pk))
	if err != nil {
		return sshfp, err
	}

	pubKeyType := pubKey.Type()
	switch {
	case pubKeyType == "ssh-dss":
		sshfp.Algorithm = AlgorithmDSS
	case pubKeyType == "ssh-rsa":
		sshfp.Algorithm = AlgorithmRSA
	case pubKeyType == "ssh-ed25519":
		sshfp.Algorithm = AlgorithmEd25519
	case strings.HasPrefix(pubKeyType, "ecdsa-sha2-"):
		sshfp.Algorithm = AlgorithmECDSA
	default:
		return sshfp, fmt.Errorf("sshfp: unsupported public key algorithm %q", pubKey.Type())
	}

	// crypto/ssh only supports SHA256 fingerprints
	sshfp.Type = TypeSHA256
	sha256Fingerprint := ssh.FingerprintSHA256(pubKey)

	// crypto/ssh only exposes public key fingerprints as SSH-compatible
	// display strings, so we have to isolate and decode the base64-encoded
	// fingerprint into bytes
	base64Fingerprint, foundPrefix := strings.CutPrefix(sha256Fingerprint, "SHA256:")
	if !foundPrefix {
		// Panic rather than return an error, because this would
		// indicate a breaking change in crypto/ssh
		panic("ssh.FingerprintSHA256() did not return the expected \"SHA256:\"-prefixed hash")
	}
	fpBytes, err := base64.RawStdEncoding.DecodeString(base64Fingerprint)
	if err != nil {
		return sshfp, err
	}

	sshfp.FingerPrint = fpBytes

	return sshfp, nil
}
