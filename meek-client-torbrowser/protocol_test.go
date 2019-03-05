package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

const timeout = 50 * time.Millisecond

var errTimedout = errors.New("timed out")

type infiniteReader struct{}

func (r *infiniteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = '\n'
	}
	return len(p), nil
}

func grepHelperAddrTimeout(r io.Reader) (string, error) {
	type result struct {
		s   string
		err error
	}
	ch := make(chan result)
	go func() {
		s, err := grepHelperAddr(r)
		ch <- result{
			s:   s,
			err: err,
		}
	}()

	select {
	case result := <-ch:
		return result.s, result.err
	case <-time.After(timeout):
		return "", errTimedout
	}
}

func TestGrepHelperAddr(t *testing.T) {
	const expectedAddr = "127.0.0.1:1000"

	// bad tests
	for _, test := range []string{
		"",
		"xmeek-http-helper: listen " + expectedAddr + "\n",
		"meek-http-helper: listen 127.0.0.1:\n",
		"meek-http-helper: listen " + expectedAddr + " \n",
		"meek-http-helper: listen " + expectedAddr + "abc\n",
	} {
		b := bytes.NewReader([]byte(test))
		s, err := grepHelperAddrTimeout(b)
		if err != io.EOF {
			t.Errorf("%q → (%q, %v), should have been %v", test, s, err, io.EOF)
		}
		// test again with an endless reader
		b = bytes.NewReader([]byte(test))
		s, err = grepHelperAddrTimeout(io.MultiReader(b, &infiniteReader{}))
		if err != errTimedout {
			t.Errorf("%q → (%q, %v), should have been %v", test, s, err, errTimedout)
		}
	}

	// good tests
	for _, test := range []string{
		"meek-http-helper: listen " + expectedAddr,
		"meek-http-helper: listen " + expectedAddr + "\njunk",
		"junk\nmeek-http-helper: listen " + expectedAddr + "\njunk",
		"meek-http-helper: listen " + expectedAddr + "\nmeek-http-helper: listen 1.2.3.4:9999\n",
	} {
		b := bytes.NewReader([]byte(test))
		s, err := grepHelperAddrTimeout(b)
		if err != nil || s != expectedAddr {
			t.Errorf("%q → (%q, %v), should have been %q", test, s, err, expectedAddr)
		}
		// test again with an endless reader
		b = bytes.NewReader([]byte(test))
		s, err = grepHelperAddrTimeout(io.MultiReader(b, &infiniteReader{}))
		if err != nil || s != expectedAddr {
			t.Errorf("%q → (%q, %v), should have been %q", test, s, err, expectedAddr)
		}
	}
}
