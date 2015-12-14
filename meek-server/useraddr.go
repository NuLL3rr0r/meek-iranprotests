package main

import (
	"fmt"
	"net"
	"net/http"
)

// Return the original client IP address as best as it can be determined.
func originalClientIP(req *http.Request) (net.IP, error) {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("cannot parse %q as IP address")
	}
	return ip, nil
}
