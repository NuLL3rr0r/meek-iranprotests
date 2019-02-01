package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"
)

const testHost = "test.example"
const testPort = "1234"
const testAddr = testHost + ":" + testPort
const testUsername = "username"
const testPassword = "password"

// Test that addrForDial returns a numeric port number. It needs to be numeric
// because we pass it as part of the authority-form URL in HTTP proxy requests.
// https://tools.ietf.org/html/rfc7230#section-5.3.3 authority-form
// https://tools.ietf.org/html/rfc3986#section-3.2.3 port
func TestAddrForDial(t *testing.T) {
	// good tests
	for _, test := range []struct {
		URL  string
		Addr string
	}{
		{"http://example.com", "example.com:80"},
		{"http://example.com/", "example.com:80"},
		{"https://example.com/", "example.com:443"},
		{"http://example.com:443/", "example.com:443"},
		{"ftp://example.com:21/", "example.com:21"},
	} {
		u, err := url.Parse(test.URL)
		if err != nil {
			panic(err)
		}
		addr, err := addrForDial(u)
		if err != nil {
			t.Errorf("%q → error %v", test.URL, err)
			continue
		}
		if addr != test.Addr {
			t.Errorf("%q → %q, expected %q", test.URL, addr, test.Addr)
		}
	}

	// bad tests
	for _, input := range []string{
		"example.com",
		"example.com:80",
		"ftp://example.com/",
	} {
		u, err := url.Parse(input)
		if err != nil {
			panic(err)
		}
		addr, err := addrForDial(u)
		if err == nil {
			t.Errorf("%q → %q, expected error", input, addr)
			continue
		}
	}
}

// Dial the given address with the given proxy, and return the http.Request that
// the proxy server would have received.
func requestResultingFromDial(t *testing.T, ln net.Listener, makeProxy func(addr net.Addr) (*httpProxy, error), network, addr string) (*http.Request, error) {
	ch := make(chan *http.Request, 1)

	go func() {
		defer func() {
			close(ch)
		}()
		conn, err := ln.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			t.Error(err)
			return
		}
		ch <- req
	}()

	pr, err := makeProxy(ln.Addr())
	if err != nil {
		return nil, err
	}
	// The Dial fails because the goroutine "server" hangs up. So ignore an
	// ErrUnexpectedEOF error.
	_, err = pr.Dial(network, addr)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, err
	}

	return <-ch, nil
}

func requestResultingFromDialHTTP(t *testing.T, makeProxy func(addr net.Addr) (*httpProxy, error), network, addr string) (*http.Request, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	return requestResultingFromDial(t, ln, makeProxy, network, addr)
}

// Test that the HTTP proxy client sends a correct request.
func TestProxyHTTPCONNECT(t *testing.T) {
	req, err := requestResultingFromDialHTTP(t, func(addr net.Addr) (*httpProxy, error) {
		return ProxyHTTP("tcp", addr.String(), nil, proxy.Direct)
	}, "tcp", testAddr)
	if err != nil {
		panic(err)
	}
	if req.Method != "CONNECT" {
		t.Errorf("expected method %q, got %q", "CONNECT", req.Method)
	}
	if req.URL.Hostname() != testHost || req.URL.Port() != testPort {
		t.Errorf("expected URL %q, got %q", testAddr, req.URL.String())
	}
	if req.Host != testAddr {
		t.Errorf("expected %q, got %q", "Host: "+req.Host, "Host: "+testAddr)
	}
}

// Test that the HTTP proxy client sends authorization credentials.
func TestProxyHTTPProxyAuthorization(t *testing.T) {
	auth := &proxy.Auth{
		User:     testUsername,
		Password: testPassword,
	}
	req, err := requestResultingFromDialHTTP(t, func(addr net.Addr) (*httpProxy, error) {
		return ProxyHTTP("tcp", addr.String(), auth, proxy.Direct)
	}, "tcp", testAddr)
	if err != nil {
		panic(err)
	}
	pa := req.Header.Get("Proxy-Authorization")
	if pa == "" {
		t.Fatalf("didn't get a Proxy-Authorization header")
	}
	// The standard library Request.BasicAuth does parsing of basic
	// authentication, but only in the Authorization header, not
	// Proxy-Authorization.
	newReq := &http.Request{
		Header: http.Header{
			"Authorization": []string{pa},
		},
	}
	username, password, ok := newReq.BasicAuth()
	if !ok {
		panic("shouldn't fail")
	}
	if username != testUsername {
		t.Errorf("expected username %q, got %q", testUsername, username)
	}
	if password != testPassword {
		t.Errorf("expected password %q, got %q", testPassword, password)
	}
}

// Create a TLS listener using a temporary self-signed certificate.
// https://golang.org/src/crypto/tls/generate_cert.go
func selfSignedTLSListen(network, addr string) (net.Listener, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(100 * time.Second)
	template := x509.Certificate{
		SerialNumber: big.NewInt(123),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	config := tls.Config{
		Certificates: []tls.Certificate{
			tls.Certificate{
				Certificate: [][]byte{cert},
				PrivateKey:  priv,
			},
		},
	}

	return tls.Listen(network, addr, &config)
}

func requestResultingFromDialHTTPS(t *testing.T, makeProxy func(addr net.Addr) (*httpProxy, error), network, addr string) (*http.Request, error) {
	ln, err := selfSignedTLSListen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	return requestResultingFromDial(t, ln, makeProxy, network, addr)
}

func TestProxyHTTPSCONNECT(t *testing.T) {
	req, err := requestResultingFromDialHTTPS(t, func(addr net.Addr) (*httpProxy, error) {
		return ProxyHTTPS("tcp", addr.String(), nil, proxy.Direct, &utls.Config{InsecureSkipVerify: true}, &utls.HelloFirefox_Auto)
	}, "tcp", testAddr)
	if err != nil {
		panic(err)
	}
	if req.Method != "CONNECT" {
		t.Errorf("expected method %q, got %q", "CONNECT", req.Method)
	}
	if req.URL.Hostname() != testHost || req.URL.Port() != testPort {
		t.Errorf("expected URL %q, got %q", testAddr, req.URL.String())
	}
	if req.Host != testAddr {
		t.Errorf("expected %q, got %q", "Host: "+req.Host, "Host: "+testAddr)
	}
}
