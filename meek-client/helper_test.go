package main

import (
	"net/url"
	"testing"
)

func TestMakeProxySpec(t *testing.T) {
	badTests := []*url.URL{
		{Scheme: "http"},
		{Scheme: "http", Host: ":"},
		{Scheme: "http", Host: "localhost"},
		{Scheme: "http", Host: "localhost:"},
		{Scheme: "http", Host: ":8080"},
		{Scheme: "http", Host: "localhost:https"},
		{Scheme: "http", Host: "localhost:8080", User: url.User("username")},
		{Scheme: "http", Host: "localhost:8080", User: url.UserPassword("username", "password")},
		{Scheme: "http", User: url.User("username"), Host: "localhost:8080"},
		{Scheme: "http", User: url.UserPassword("username", "password"), Host: "localhost:8080"},
		{Scheme: "http", Host: "localhost:-1"},
		{Scheme: "http", Host: "localhost:65536"},
		{Scheme: "socks5", Host: ":"},
		{Scheme: "socks4a", Host: ":"},
		// "socks" and "socks4" are unknown types.
		{Scheme: "socks", Host: "localhost:1080"},
		{Scheme: "socks4", Host: "localhost:1080"},
		{Scheme: "unknown", Host: "localhost:9999"},
	}
	goodTests := []struct {
		input    *url.URL
		expected ProxySpec
	}{
		{
			&url.URL{Scheme: "http", Host: "localhost:8080"},
			ProxySpec{"http", "localhost", 8080},
		},
		{
			&url.URL{Scheme: "socks5", Host: "localhost:1080"},
			ProxySpec{"socks5", "localhost", 1080},
		},
		{
			&url.URL{Scheme: "socks4a", Host: "localhost:1080"},
			ProxySpec{"socks4a", "localhost", 1080},
		},
	}

	for _, input := range badTests {
		_, err := makeProxySpec(input)
		if err == nil {
			t.Errorf("%q unexpectedly succeeded", input)
		}
	}

	for _, test := range goodTests {
		spec, err := makeProxySpec(test.input)
		if err != nil {
			t.Fatalf("%q unexpectedly returned an error: %s", test.input, err)
		}
		if *spec != test.expected {
			t.Errorf("%q → %q (expected %q)", test.input, spec, test.expected)
		}
	}
}
