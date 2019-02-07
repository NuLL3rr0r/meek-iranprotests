package main

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

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
func requestResultingFromDial(t *testing.T, makeProxy func(addr net.Addr) (*httpProxy, error), network, addr string) (*http.Request, error) {
	ch := make(chan *http.Request, 1)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()

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

// Test that the HTTP proxy client sends a correct request.
func TestProxyHTTPCONNECT(t *testing.T) {
	req, err := requestResultingFromDial(t, func(addr net.Addr) (*httpProxy, error) {
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
	req, err := requestResultingFromDial(t, func(addr net.Addr) (*httpProxy, error) {
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
