/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package redistls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCertPair writes a self-signed certificate and its key as PEM files and returns their paths.
func writeCertPair(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
	writeFile(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeFile(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPath, keyPath
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestBuildDisabled(t *testing.T) {
	// Other fields are ignored while TLS is off, even when they point at nothing.
	cfg, fp, err := Config{CAFile: "/does/not/exist", CertFile: "x"}.Build()
	if cfg != nil || fp != "" || err != nil {
		t.Fatalf("disabled: got cfg=%v fp=%q err=%v, want nil, \"\", nil", cfg, fp, err)
	}
}

func TestBuildEnabledSystemTrustStore(t *testing.T) {
	cfg, fp, err := Config{Enabled: true}.Build()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil || fp == "" {
		t.Fatal("expected a TLS config and fingerprint")
	}
	if cfg.RootCAs != nil {
		t.Error("RootCAs should be nil (system trust store) when ca_file is empty")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", cfg.MinVersion)
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should default to false")
	}
}

func TestBuildFieldsMapped(t *testing.T) {
	dir := t.TempDir()
	caPath, _ := writeCertPair(t, dir, "ca")
	cfg, _, err := Config{Enabled: true, CAFile: caPath, ServerName: "redis.internal", InsecureSkipVerify: true}.Build()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs not set from ca_file")
	}
	if cfg.ServerName != "redis.internal" {
		t.Errorf("ServerName = %q, want redis.internal", cfg.ServerName)
	}
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify not mapped")
	}
}

func TestBuildMutualTLS(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeCertPair(t, dir, "client")
	cfg, _, err := Config{Enabled: true, CertFile: certPath, KeyFile: keyPath}.Build()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates len = %d, want 1", len(cfg.Certificates))
	}
}

func TestBuildErrors(t *testing.T) {
	dir := t.TempDir()
	certA, keyA := writeCertPair(t, dir, "a")
	_, keyB := writeCertPair(t, dir, "b")
	notPEM := filepath.Join(dir, "not-pem.txt")
	writeFile(t, notPEM, []byte("hello"))

	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"missing ca_file", Config{Enabled: true, CAFile: filepath.Join(dir, "missing.pem")}, "reading ca_file"},
		{"ca_file not PEM", Config{Enabled: true, CAFile: notPEM}, "no valid PEM certificates"},
		{"cert without key", Config{Enabled: true, CertFile: certA}, "must be set together"},
		{"key without cert", Config{Enabled: true, KeyFile: keyA}, "must be set together"},
		{"missing cert_file", Config{Enabled: true, CertFile: filepath.Join(dir, "missing.crt"), KeyFile: keyA}, "reading cert_file"},
		{"mismatched pair", Config{Enabled: true, CertFile: certA, KeyFile: keyB}, "loading client certificate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := tt.cfg.Build()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestFingerprint(t *testing.T) {
	dir := t.TempDir()
	caPath, _ := writeCertPair(t, dir, "ca")
	base := Config{Enabled: true, CAFile: caPath}

	_, fp1, _ := base.Build()
	_, fp2, _ := base.Build()
	if fp1 != fp2 {
		t.Fatal("identical settings must produce the same fingerprint")
	}

	withName := base
	withName.ServerName = "other"
	if _, fp, _ := withName.Build(); fp == fp1 {
		t.Error("server_name change must change the fingerprint")
	}

	withSkip := base
	withSkip.InsecureSkipVerify = true
	if _, fp, _ := withSkip.Build(); fp == fp1 {
		t.Error("insecure_skip_verify change must change the fingerprint")
	}

	// Rotating the CA file's contents (same path) must change the fingerprint so a
	// reload gets a new client instead of reusing one built with the old CA.
	rotated, _ := writeCertPair(t, dir, "ca-rotated")
	data, err := os.ReadFile(rotated)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, caPath, data)
	if _, fp, _ := base.Build(); fp == fp1 {
		t.Error("CA file content change must change the fingerprint")
	}
}
