// package dnsresolver ...
package dnsresolver

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
)

// tlsConfigPin ...
func tlsConfigPin(r *Resolver) *tls.Config {
	tlsConfig := &tls.Config{
		InsecureSkipVerify:     false,
		SessionTicketsDisabled: true,
		Renegotiation:          0,
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		CipherSuites:           []uint16{tls.TLS_CHACHA20_POLY1305_SHA256},
		CurvePreferences:       []tls.CurveID{tls.X25519},
	}
	if r.TLSKeyPin != _empty {
		tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if !pinVerifyState(r.TLSKeyPin, &state) {
				return errors.New(_errKeyPin + r.Name)
			}
			return nil
		}
	}
	return tlsConfig
}

// pinVerifyState ...
func pinVerifyState(keyPin string, state *tls.ConnectionState) bool {
	if len(state.PeerCertificates) > 0 {
		if keyPin == keyPinBase64(state.PeerCertificates[0]) {
			return true
		}
	}
	return false
}

// keyPinBase64 ...
func keyPinBase64(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(h[:])
}
