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

package ratelimit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// testPKI is a throwaway CA plus a server and a client certificate signed by it.
type testPKI struct {
	caFile, clientCert, clientKey string
	caPool                        *x509.CertPool
	server                        tls.Certificate
}

func newTestPKI(t *testing.T) testPKI {
	t.Helper()
	dir := t.TempDir()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	issue := func(serial int64, cn string, usage x509.ExtKeyUsage) ([]byte, []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatalf("issue %s: %v", cn, err)
		}
		keyDER, _ := x509.MarshalECPrivateKey(key)
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
			pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	}

	serverCert, serverKey := issue(2, "redis", x509.ExtKeyUsageServerAuth)
	clientCert, clientKey := issue(3, "gateway", x509.ExtKeyUsageClientAuth)
	server, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatalf("server key pair: %v", err)
	}

	p := testPKI{
		caFile:     filepath.Join(dir, "ca.crt"),
		clientCert: filepath.Join(dir, "client.crt"),
		clientKey:  filepath.Join(dir, "client.key"),
		caPool:     x509.NewCertPool(),
		server:     server,
	}
	p.caPool.AddCert(caCert)
	for path, data := range map[string][]byte{
		p.caFile:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		p.clientCert: clientCert,
		p.clientKey:  clientKey,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return p
}

// redisTLSParams returns advanced-ratelimit params for a Redis backend at addr with
// failureMode=closed, so a failed connection surfaces as a GetPolicy error.
func redisTLSParams(t *testing.T, addr string, tlsParams map[string]interface{}) map[string]interface{} {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %s: %v", addr, err)
	}
	port, _ := strconv.Atoi(portStr)
	redisParams := map[string]interface{}{
		"host":              host,
		"port":              float64(port),
		"failureMode":       "closed",
		"connectionTimeout": "2s",
	}
	if tlsParams != nil {
		redisParams["tls"] = tlsParams
	}
	params := basicQuotaParams()
	params["backend"] = "redis"
	params["redis"] = redisParams
	return params
}

func TestGetPolicy_RedisTLS(t *testing.T) {
	pki := newTestPKI(t)
	mr, err := miniredis.RunTLS(&tls.Config{Certificates: []tls.Certificate{pki.server}})
	if err != nil {
		t.Fatalf("miniredis TLS: %v", err)
	}
	defer mr.Close()

	t.Run("plaintext client against TLS Redis fails", func(t *testing.T) {
		_, err := GetPolicy(policy.PolicyMetadata{RouteName: "tls-plaintext"}, redisTLSParams(t, mr.Addr(), nil))
		if err == nil || !strings.Contains(err.Error(), "redis connection failed") {
			t.Fatalf("err = %v, want redis connection failure", err)
		}
	})

	t.Run("tls enabled with ca_file connects", func(t *testing.T) {
		params := redisTLSParams(t, mr.Addr(), map[string]interface{}{"enabled": true, "caFile": pki.caFile})
		if _, err := GetPolicy(policy.PolicyMetadata{RouteName: "tls-ok"}, params); err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
	})

	t.Run("tls enabled without trusting the CA fails verification", func(t *testing.T) {
		params := redisTLSParams(t, mr.Addr(), map[string]interface{}{"enabled": true, "serverName": "127.0.0.1"})
		_, err := GetPolicy(policy.PolicyMetadata{RouteName: "tls-untrusted"}, params)
		if err == nil || !strings.Contains(err.Error(), "certificate") {
			t.Fatalf("err = %v, want certificate verification failure", err)
		}
	})

	t.Run("insecureSkipVerify connects without the CA", func(t *testing.T) {
		params := redisTLSParams(t, mr.Addr(), map[string]interface{}{"enabled": true, "insecureSkipVerify": true})
		if _, err := GetPolicy(policy.PolicyMetadata{RouteName: "tls-skip"}, params); err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
	})

	t.Run("bad ca_file fails even with failureMode open", func(t *testing.T) {
		params := redisTLSParams(t, mr.Addr(), map[string]interface{}{"enabled": true, "caFile": "/does/not/exist.pem"})
		params["redis"].(map[string]interface{})["failureMode"] = "open"
		_, err := GetPolicy(policy.PolicyMetadata{RouteName: "tls-bad-ca"}, params)
		if err == nil || !strings.Contains(err.Error(), "ca_file") {
			t.Fatalf("err = %v, want ca_file error", err)
		}
	})
}

func TestGetPolicy_RedisMutualTLS(t *testing.T) {
	pki := newTestPKI(t)
	mr, err := miniredis.RunTLS(&tls.Config{
		Certificates: []tls.Certificate{pki.server},
		ClientCAs:    pki.caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	})
	if err != nil {
		t.Fatalf("miniredis TLS: %v", err)
	}
	defer mr.Close()

	t.Run("without client certificate fails", func(t *testing.T) {
		params := redisTLSParams(t, mr.Addr(), map[string]interface{}{"enabled": true, "caFile": pki.caFile})
		if _, err := GetPolicy(policy.PolicyMetadata{RouteName: "mtls-no-cert"}, params); err == nil {
			t.Fatal("expected failure when Redis requires a client certificate")
		}
	})

	t.Run("with client certificate connects", func(t *testing.T) {
		params := redisTLSParams(t, mr.Addr(), map[string]interface{}{
			"enabled":  true,
			"caFile":   pki.caFile,
			"certFile": pki.clientCert,
			"keyFile":  pki.clientKey,
		})
		if _, err := GetPolicy(policy.PolicyMetadata{RouteName: "mtls-ok"}, params); err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
	})
}

func TestRedisClientRegistry_TLSFingerprint(t *testing.T) {
	opts := func() *redis.Options { return &redis.Options{Addr: "127.0.0.1:1", DialTimeout: 10 * time.Millisecond} }

	plain, _, _ := getOrCreateRedisClient(opts(), "", 10*time.Millisecond)
	tlsA, createdA, _ := getOrCreateRedisClient(opts(), "fp-a", 10*time.Millisecond)
	tlsA2, createdA2, _ := getOrCreateRedisClient(opts(), "fp-a", 10*time.Millisecond)
	tlsB, createdB, _ := getOrCreateRedisClient(opts(), "fp-b", 10*time.Millisecond)

	if !createdA || tlsA == plain {
		t.Error("TLS settings must not reuse the plaintext client for the same address")
	}
	if createdA2 || tlsA2 != tlsA {
		t.Error("identical TLS settings must reuse the same client")
	}
	if !createdB || tlsB == tlsA {
		t.Error("different TLS settings must create a distinct client")
	}
}
