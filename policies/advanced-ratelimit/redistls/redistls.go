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

// Package redistls builds the TLS configuration for the Redis clients used by the
// rate-limit policies (advanced-ratelimit and every policy that delegates to it, plus
// cost-based-model-routing). It is the single implementation of the
// [policy_configurations.ratelimit_v1.redis.tls] block so the policies cannot drift.
package redistls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
)

// Config mirrors the redis.tls policy parameters.
type Config struct {
	Enabled            bool
	CAFile             string // PEM CA bundle; empty = system trust store
	ServerName         string // empty = host from the dial address
	InsecureSkipVerify bool
	CertFile           string // client certificate for mTLS; set together with KeyFile
	KeyFile            string // client private key for mTLS; set together with CertFile
}

// Build returns the *tls.Config to set on redis.Options.TLSConfig, and a fingerprint
// that identifies it for the shared-client registries (a *tls.Config is not comparable).
// It returns (nil, "", nil) when TLS is disabled, which keeps the plaintext behaviour.
//
// All files are read and parsed here, so a wrong path, a non-PEM CA file or a
// mismatched certificate/key pair fails when the policy is created rather than as an
// opaque handshake error on the first request. The fingerprint covers the file
// contents, so rotated certificates produce a new client on the next policy reload.
func (c Config) Build() (*tls.Config, string, error) {
	if !c.Enabled {
		return nil, "", nil
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         c.ServerName,
		InsecureSkipVerify: c.InsecureSkipVerify, //nolint:gosec // opt-in, warned about by the caller
	}

	fp := sha256.New()
	fmt.Fprintf(fp, "server=%s|skip=%s|", c.ServerName, strconv.FormatBool(c.InsecureSkipVerify))

	if c.CAFile != "" {
		caPEM, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, "", fmt.Errorf("redis.tls: reading ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, "", fmt.Errorf("redis.tls: ca_file %q contains no valid PEM certificates", c.CAFile)
		}
		tlsConfig.RootCAs = pool
		fp.Write([]byte("ca="))
		fp.Write(caPEM)
		fp.Write([]byte("|"))
	}

	if c.CertFile != "" || c.KeyFile != "" {
		if c.CertFile == "" || c.KeyFile == "" {
			return nil, "", errors.New("redis.tls: cert_file and key_file must be set together")
		}
		certPEM, err := os.ReadFile(c.CertFile)
		if err != nil {
			return nil, "", fmt.Errorf("redis.tls: reading cert_file: %w", err)
		}
		keyPEM, err := os.ReadFile(c.KeyFile)
		if err != nil {
			return nil, "", fmt.Errorf("redis.tls: reading key_file: %w", err)
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, "", fmt.Errorf("redis.tls: loading client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{pair}
		fp.Write([]byte("cert="))
		fp.Write(certPEM)
		fp.Write([]byte("|key="))
		fp.Write(keyPEM)
	}

	return tlsConfig, hex.EncodeToString(fp.Sum(nil)), nil
}
