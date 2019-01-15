package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"time"
)

// The code in this file has to do with communication between meek-client and
// the meek-http-helper browser extension.

type JSONRequest struct {
	Method string            `json:"method,omitempty"`
	URL    string            `json:"url,omitempty"`
	Header map[string]string `json:"header,omitempty"`
	Body   []byte            `json:"body,omitempty"`
	Proxy  *ProxySpec        `json:"proxy,omitempty"`
}

type JSONResponse struct {
	Error  string `json:"error,omitempty"`
	Status int    `json:"status"`
	Body   []byte `json:"body"`
}

// ProxySpec encodes information we need to connect through a proxy.
type ProxySpec struct {
	// Acceptable values for Type are as in proposal 232: "http", "socks5",
	// or "socks4a".
	Type string `json:"type"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type HelperRoundTripper struct {
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Return a ProxySpec suitable for the proxy URL in u.
func makeProxySpec(u *url.URL) (*ProxySpec, error) {
	spec := new(ProxySpec)
	var err error
	var portStr string
	var port uint64

	if u == nil {
		// No proxy.
		return nil, nil
	}

	// Firefox's nsIProxyInfo doesn't allow credentials.
	if u.User != nil {
		return nil, fmt.Errorf("proxy URLs with a username or password can't be used with the helper")
	}

	switch u.Scheme {
	case "http", "socks5", "socks4a":
		spec.Type = u.Scheme
	default:
		return nil, fmt.Errorf("unknown scheme")
	}

	spec.Host, portStr, err = net.SplitHostPort(u.Host)
	if err != nil {
		return nil, err
	}
	if spec.Host == "" {
		return nil, fmt.Errorf("missing host")
	}
	port, err = strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, err
	}
	spec.Port = int(port)

	return spec, nil
}

func (rt *HelperRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s, err := net.DialTCP("tcp", nil, options.HelperAddr)
	if err != nil {
		return nil, err
	}
	defer s.Close()

	// Encode our JSON.
	jsonReq := JSONRequest{
		Method: req.Method,
		URL:    req.URL.String(),
		Header: make(map[string]string),
		Body:   make([]byte, 0),
	}

	// We take only the first value for each header key, due to limitations
	// in the helper JSON protocol.
	for key, values := range req.Header {
		if len(values) == 0 {
			continue
		}
		value := values[0]
		key = textproto.CanonicalMIMEHeaderKey(key)
		jsonReq.Header[key] = value
	}
	// req.Host overrides req.Header.
	if req.Host != "" {
		jsonReq.Header["Host"] = req.Host
	}

	if req.Body != nil {
		jsonReq.Body, err = ioutil.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		err = req.Body.Close()
		if err != nil {
			return nil, err
		}
	}

	jsonReq.Proxy, err = makeProxySpec(options.ProxyURL)
	if err != nil {
		return nil, err
	}
	encReq, err := json.Marshal(&jsonReq)
	if err != nil {
		return nil, err
	}
	// log.Printf("encoded %s", encReq)

	// Send the request.
	s.SetWriteDeadline(time.Now().Add(rt.WriteTimeout))
	err = binary.Write(s, binary.BigEndian, uint32(len(encReq)))
	if err != nil {
		return nil, err
	}
	_, err = s.Write(encReq)
	if err != nil {
		return nil, err
	}

	// Read the response.
	var length uint32
	s.SetReadDeadline(time.Now().Add(rt.ReadTimeout))
	err = binary.Read(s, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if length > maxHelperResponseLength {
		return nil, fmt.Errorf("helper's returned data is too big (%d > %d)",
			length, maxHelperResponseLength)

	}
	encResp := make([]byte, length)
	_, err = io.ReadFull(s, encResp)
	if err != nil {
		return nil, err
	}
	// log.Printf("received %s", encResp)

	// Decode their JSON.
	var jsonResp JSONResponse
	err = json.Unmarshal(encResp, &jsonResp)
	if err != nil {
		return nil, err
	}
	if jsonResp.Error != "" {
		return nil, fmt.Errorf("helper returned error: %s", jsonResp.Error)
	}

	// Mock up an HTTP response.
	resp := http.Response{
		Status:        http.StatusText(jsonResp.Status),
		StatusCode:    jsonResp.Status,
		Body:          ioutil.NopCloser(bytes.NewReader(jsonResp.Body)),
		ContentLength: int64(len(jsonResp.Body)),
	}
	return &resp, nil
}

// Do an HTTP roundtrip through the configured browser extension, using the
// payload data in buf and the request metadata in info.
func roundTripWithHelper(buf []byte, info *RequestInfo) (*http.Response, error) {
	var body io.Reader
	if len(buf) > 0 {
		// Leave body == nil when buf is empty. A nil body is an
		// explicit signal that the body is empty. An empty
		// *bytes.Reader or the magic value http.NoBody are supposed to
		// be equivalent ways to signal an empty body, but in Go 1.8 the
		// HTTP/2 code only understands nil. Not leaving body == nil
		// causes the Content-Length header to be omitted from HTTP/2
		// requests, which in some cases can cause the server to return
		// a 411 "Length Required" error. See
		// https://bugs.torproject.org/22865.
		body = bytes.NewReader(buf)
	}
	req, err := http.NewRequest("POST", info.URL.String(), body)
	if err != nil {
		return nil, err
	}
	if info.Host != "" {
		req.Host = info.Host
	}
	req.Header.Set("X-Session-Id", info.SessionID)
	return helperRoundTripper.RoundTrip(req)
}
