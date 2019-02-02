package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestCopyPublicFieldsHTTPTransport(t *testing.T) {
	src := http.DefaultTransport.(*http.Transport)
	dst := &http.Transport{}
	copyPublicFields(dst, src)
	// Test various fields that we might care about a copy of http.Transport
	// having.
	if dst.DisableKeepAlives != src.DisableKeepAlives {
		t.Errorf("mismatch on DisableKeepAlives")
	}
	if dst.DisableCompression != src.DisableCompression {
		t.Errorf("mismatch on DisableCompression")
	}
	if dst.MaxIdleConns != src.MaxIdleConns {
		t.Errorf("mismatch on MaxIdleConns")
	}
	if dst.MaxIdleConnsPerHost != src.MaxIdleConnsPerHost {
		t.Errorf("mismatch on MaxIdleConnsPerHost")
	}
	if dst.MaxConnsPerHost != src.MaxConnsPerHost {
		t.Errorf("mismatch on MaxConnsPerHost")
	}
	if dst.IdleConnTimeout != src.IdleConnTimeout {
		t.Errorf("mismatch on IdleConnTimeout")
	}
	if dst.ResponseHeaderTimeout != src.ResponseHeaderTimeout {
		t.Errorf("mismatch on ResponseHeaderTimeout")
	}
	if dst.ExpectContinueTimeout != src.ExpectContinueTimeout {
		t.Errorf("mismatch on ExpectContinueTimeout")
	}
	if dst.MaxResponseHeaderBytes != src.MaxResponseHeaderBytes {
		t.Errorf("mismatch on MaxResponseHeaderBytes")
	}
}

// Test that the name lookup of NewUTLSRoundTripper is case-insensitive.
func TestNewUTLSRoundTripperCase(t *testing.T) {
	mixed, err := NewUTLSRoundTripper("HelloFirefox_Auto", nil, nil)
	if err != nil {
		t.Fatalf("error on %q: %v", "HelloFirefox_Auto", err)
	}
	upper, err := NewUTLSRoundTripper("HELLOFIREFOX_AUTO", nil, nil)
	if err != nil {
		t.Fatalf("error on %q: %v", "HELLOFIREFOX_AUTO", err)
	}
	lower, err := NewUTLSRoundTripper("hellofirefox_auto", nil, nil)
	if err != nil {
		t.Fatalf("error on %q: %v", "hellofirefox_auto", err)
	}
	if mixed.(*UTLSRoundTripper).clientHelloID != upper.(*UTLSRoundTripper).clientHelloID ||
		upper.(*UTLSRoundTripper).clientHelloID != lower.(*UTLSRoundTripper).clientHelloID {
		t.Fatalf("mismatch %p %p %p",
			mixed.(*UTLSRoundTripper).clientHelloID,
			upper.(*UTLSRoundTripper).clientHelloID,
			lower.(*UTLSRoundTripper).clientHelloID)
	}
}

// Return a byte slice which is the ClientHello sent when rt does a RoundTrip.
// Opens a temporary listener on an ephemeral port on localhost. The host you
// provide can be an IP address like "127.0.0.1" or a name like "localhost", but
// it has to resolve to localhost.
func clientHelloResultingFromRoundTrip(t *testing.T, host string, rt *UTLSRoundTripper) ([]byte, error) {
	ch := make(chan []byte, 1)

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
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			t.Error(err)
			return
		}
		ch <- buf[:n]
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		return nil, err
	}
	u := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, port),
	}
	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		return nil, err
	}
	// The RoundTrip fails because the goroutine "server" hangs up. So
	// ignore an EOF error.
	_, err = rt.RoundTrip(req)
	if err != nil && err != io.EOF {
		return nil, err
	}

	return <-ch, nil
}

// Test that a uTLS RoundTripper actually does something to the TLS Client
// Hello. We don't check all the ClientHelloIDs; this is just a guard against a
// catastrophic incompatibility or something else that makes uTLS stop working.
func TestUTLSClientHello(t *testing.T) {
	// We use HelloIOS_11_1 because its lengthy ALPN means we will not
	// confuse it with a native Go fingerprint, and lack of GREASE means we
	// do not have to account for many variations.
	rt, err := NewUTLSRoundTripper("HelloIOS_11_1", &utls.Config{InsecureSkipVerify: true, ServerName: "localhost"}, nil)
	if err != nil {
		panic(err)
	}

	buf, err := clientHelloResultingFromRoundTrip(t, "127.0.0.1", rt.(*UTLSRoundTripper))
	// A poor man's regexp matching because the regexp package only works on
	// UTF-8–encoded strings, not arbitrary byte slices. Every byte matches
	// itself, except '.' which matches anything. NB '.' and '\x2e' are the
	// same.
	pattern := "" +
		// Handshake, Client Hello, TLS 1.2, Client Random
		"\x16\x03\x01\x01\x01\x01\x00\x00\xfd\x03\x03................................" +
		// Session ID
		"\x20................................" +
		// Ciphersuites and compression methods
		"\x00\x28\xc0\x2c\xc0\x2b\xc0\x24\xc0\x23\xc0\x0a\xc0\x09\xcc\xa9\xc0\x30\xc0\x2f\xc0\x28\xc0\x27\xc0\x14\xc0\x13\xcc\xa8\x00\x9d\x00\x9c\x00\x3d\x00\x3c\x00\x35\x00\x2f\x01\x00" +
		// Extensions
		"\x00\x8c\xff\x01\x00\x01\x00" +
		"\x00\x00\x00\x0e\x00\x0c\x00\x00\x09localhost" +
		"\x00\x17\x00\x00" +
		"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01" +
		"\x00\x05\x00\x05\x01\x00\x00\x00\x00" +
		"\x33\x74\x00\x00" +
		"\x00\x12\x00\x00" +
		"\x00\x10\x00\x30\x00\x2e\x02\x68\x32\x05\x68\x32\x2d\x31\x36\x05\x68\x32\x2d\x31\x35\x05\x68\x32\x2d\x31\x34\x08\x73\x70\x64\x79\x2f\x33\x2e\x31\x06\x73\x70\x64\x79\x2f\x33\x08\x68\x74\x74\x70\x2f\x31\x2e\x31" +
		"\x00\x0b\x00\x02\x01\x00" +
		"\x00\x0a\x00\x0a\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"
	if len(buf) != len(pattern) {
		t.Errorf("fingerprint was not as expected: %+q", buf)
	}
	for i := 0; i < len(pattern); i++ {
		a := buf[i]
		b := pattern[i]
		if b != '.' && a != b {
			t.Fatalf("fingerprint mismatch a position %v: %+q", i, buf)
		}
	}
}

func TestUTLSServerName(t *testing.T) {
	const clientHelloIDName = "HelloFirefox_63"

	// No ServerName, dial IP address. Results in an invalid server_name
	// extension with a 0-length host_name. Not sure if that's what it
	// should do, but check if the behavior ever changes.
	rt, err := NewUTLSRoundTripper(clientHelloIDName, &utls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		panic(err)
	}
	buf, err := clientHelloResultingFromRoundTrip(t, "127.0.0.1", rt.(*UTLSRoundTripper))
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(buf, []byte("\x00\x00\x00\x05\x00\x03\x00\x00\x00")) {
		t.Errorf("expected 0-length server_name extension with no ServerName and IP address dial")
	}

	// No ServerName, dial hostname. server_name extension should come from
	// the dial address.
	rt, err = NewUTLSRoundTripper(clientHelloIDName, &utls.Config{InsecureSkipVerify: true}, nil)
	if err != nil {
		panic(err)
	}
	buf, err = clientHelloResultingFromRoundTrip(t, "localhost", rt.(*UTLSRoundTripper))
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(buf, []byte("\x00\x00\x00\x0e\x00\x0c\x00\x00\x09localhost")) {
		t.Errorf("expected \"localhost\" server_name extension with no ServerName and hostname dial")
	}

	// Given ServerName, dial IP address. server_name extension should from
	// the ServerName.
	rt, err = NewUTLSRoundTripper(clientHelloIDName, &utls.Config{InsecureSkipVerify: true, ServerName: "test.example"}, nil)
	if err != nil {
		panic(err)
	}
	buf, err = clientHelloResultingFromRoundTrip(t, "127.0.0.1", rt.(*UTLSRoundTripper))
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(buf, []byte("\x00\x00\x00\x11\x00\x0f\x00\x00\x0ctest.example")) {
		t.Errorf("expected \"test.example\" server_name extension with given ServerName and IP address dial")
	}

	// Given ServerName, dial hostname. server_name extension should from
	// the ServerName.
	rt, err = NewUTLSRoundTripper(clientHelloIDName, &utls.Config{InsecureSkipVerify: true, ServerName: "test.example"}, nil)
	if err != nil {
		panic(err)
	}
	buf, err = clientHelloResultingFromRoundTrip(t, "localhost", rt.(*UTLSRoundTripper))
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(buf, []byte("\x00\x00\x00\x11\x00\x0f\x00\x00\x0ctest.example")) {
		t.Errorf("expected \"test.example\" server_name extension with given ServerName and hostname dial")
	}
}

// Test that HTTP requests (which don't go through the uTLS code path) still use
// any proxy that's configured on the UTLSRoundTripper.
func TestUTLSHTTPWithProxy(t *testing.T) {
	// Make a web server that we should *not* be able to reach.
	server := &http.Server{
		Handler: http.NotFoundHandler(),
	}
	serverLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer serverLn.Close()
	go server.Serve(serverLn)

	// Make a non-functional proxy server.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer proxyLn.Close()
	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err == nil {
				conn.Close() // go away
			}
		}
	}()

	// Try to access the web server through the non-functional proxy.
	for _, proxyURL := range []url.URL{
		url.URL{Scheme: "socks5", Host: proxyLn.Addr().String()},
	} {
		rt, err := NewUTLSRoundTripper("HelloFirefox_63", &utls.Config{InsecureSkipVerify: true}, &proxyURL)
		if err != nil {
			panic(err)
		}
		fetchURL := url.URL{Scheme: "http", Host: serverLn.Addr().String()}
		req, err := http.NewRequest("GET", fetchURL.String(), nil)
		if err != nil {
			panic(err)
		}
		_, err = rt.RoundTrip(req)
		if err == nil {
			t.Errorf("fetch of %s through %s proxy should have failed", &fetchURL, proxyURL.Scheme)
		}
	}
}
