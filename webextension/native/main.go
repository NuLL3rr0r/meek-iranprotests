// This program is the native part of the meek-http-helper WebExtension. Its
// purpose is to open a localhost TCP socket for communication with meek-client
// in its --helper mode (the WebExtension cannot open a socket on its own). This
// program is also in charge of multiplexing the many incoming socket
// connections over the single shared stdio stream to/from the WebExtension.

package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const (
	// How long we'll wait for meek-client to send a request spec or receive
	// a response spec over the socket. This can be short because it's all
	// localhost communication.
	localReadTimeout  = 2 * time.Second
	localWriteTimeout = 2 * time.Second

	// How long we'll wait, after sending a request spec to the browser, for
	// the browser to come back with a response. This is meant to be
	// generous; its purpose is to allow reclaiming memory in case the
	// browser somehow drops a request spec.
	roundTripTimeout = 120 * time.Second

	// Self-defense against a malfunctioning meek-client. We'll refuse to
	// read encoded requests that are longer than this.
	maxRequestSpecLength = 1000000

	// Self-defense against a malfunctioning browser. We'll refuse to
	// receive WebExtension messages that are longer than this.
	maxWebExtensionMessageLength = 1000000
)

// We receive multiple (possibly concurrent) connections over our listening
// socket, and we must multiplex all their requests/responses to/from the
// browser over the single shared stdio stream. When roundTrip sends a
// webExtensionRoundTripRequest to the browser, creates a channel to receive the
// response, and stores the ID–channel mapping in requestResponseMap. When
// inFromBrowserLoop receives a webExtensionRoundTripResponse from the browser,
// it is tagged with the same ID as the corresponding request. inFromBrowserLoop
// looks up the matching channel and sends the response over it.
var requestResponseMap = make(map[string]chan<- responseSpec)
var requestResponseMapLock sync.Mutex

// A specification of an HTTP request, as received via the socket from
// "meek-client --helper".
type requestSpec interface{}

// A specification of an HTTP request or an error, as sent via the socket to
// "meek-client --helper".
type responseSpec interface{}

// A "roundtrip" command sent out to the browser over the stdout stream. It
// encapsulates a requestSpec as received from the socket, plus
// command:"roundtrip" and an ID, which used to match up the eventual reply with
// this request.
//
// command:"roundtrip" is to disambiguate with the other command we may send,
// "report-address".
type webExtensionRoundTripRequest struct {
	Command string      `json:"command"` // "roundtrip"
	ID      string      `json:"id"`
	Request requestSpec `json:"request"`
}

// A message received from the the browser over the stdin stream. It
// encapsulates a responseSpec along with the ID of the webExtensionResponse
// that resulted in this response.
type webExtensionRoundTripResponse struct {
	ID       string       `json:"id"`
	Response responseSpec `json:"response"`
}

// Read a requestSpec (receive from "meek-client --helper").
//
// The meek-client protocol is coincidentally similar to the WebExtension stdio
// protocol: a 4-byte length, followed by a JSON object of that length. The only
// difference is the byte order of the length: meek-client's is big-endian,
// while WebExtension's is native-endian.
func readRequestSpec(r io.Reader) (requestSpec, error) {
	var length uint32
	err := binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return nil, err
	}
	if length > maxRequestSpecLength {
		return nil, fmt.Errorf("request spec is too long: %d (max %d)", length, maxRequestSpecLength)
	}

	encodedSpec := make([]byte, length)
	_, err = io.ReadFull(r, encodedSpec)
	if err != nil {
		return nil, err
	}

	spec := new(requestSpec)
	err = json.Unmarshal(encodedSpec, spec)
	if err != nil {
		return nil, err
	}

	return spec, nil
}

// Write a responseSpec (send to "meek-client --helper").
func writeResponseSpec(w io.Writer, spec responseSpec) error {
	encodedSpec, err := json.Marshal(spec)
	if err != nil {
		panic(err)
	}

	// len returns int, which is specified to be either 32 or 64 bits, so it
	// will never be truncated when converting to uint64.
	// https://golang.org/ref/spec#Numeric_types
	length := len(encodedSpec)
	if uint64(length) > math.MaxUint32 {
		return fmt.Errorf("response spec is too long to represent: %d", length)
	}
	err = binary.Write(w, binary.BigEndian, uint32(length))
	if err != nil {
		return err
	}

	_, err = w.Write(encodedSpec)
	return err
}

// Receive a WebExtension message.
// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging#App_side
func recvWebExtensionMessage(r io.Reader) ([]byte, error) {
	var length uint32
	err := binary.Read(r, NativeEndian, &length)
	if err != nil {
		return nil, err
	}
	if length > maxWebExtensionMessageLength {
		return nil, fmt.Errorf("WebExtension message is too long: %d (max %d)", length, maxWebExtensionMessageLength)
	}
	message := make([]byte, length)
	_, err = io.ReadFull(r, message)
	if err != nil {
		return nil, err
	}
	return message, nil
}

// Send a WebExtension message.
// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging#App_side
func sendWebExtensionMessage(w io.Writer, message []byte) error {
	// len returns int, which is specified to be either 32 or 64 bits, so it
	// will never be truncated when converting to uint64.
	// https://golang.org/ref/spec#Numeric_types
	length := len(message)
	if uint64(length) > math.MaxUint32 {
		return fmt.Errorf("WebExtension message is too long to represent: %d", length)
	}
	err := binary.Write(w, NativeEndian, uint32(length))
	if err != nil {
		return err
	}
	_, err = w.Write(message)
	return err
}

// Read a responseSpec from the socket and wrap it in a
// webExtensionRoundTripRequest, tagging it with a random ID. Register the ID in
// requestResponseMap and forward the webExtensionRoundTripRequest to the
// browser. Wait for the browser to send back a webExtensionRoundTripResponse
// (which actually happens in inFromBrowserLoop--that function uses the ID to
// find this goroutine again). Return a responseSpec object or an error.
func roundTrip(conn net.Conn, outToBrowserChan chan<- []byte) (responseSpec, error) {
	err := conn.SetReadDeadline(time.Now().Add(localReadTimeout))
	if err != nil {
		return nil, err
	}
	req, err := readRequestSpec(conn)
	if err != nil {
		return nil, err
	}

	// Generate an ID that will allow us to match a response to this request.
	idRaw := make([]byte, 8)
	_, err = rand.Read(idRaw)
	if err != nil {
		return nil, err
	}
	id := hex.EncodeToString(idRaw)

	// This is the channel over which inFromBrowserLoop will send the
	// response. Register it in requestResponseMap to enable
	// inFromBrowserLoop to match the corresponding response to it.
	responseSpecChan := make(chan responseSpec)
	requestResponseMapLock.Lock()
	requestResponseMap[id] = responseSpecChan
	requestResponseMapLock.Unlock()

	// Encode and send the message to the browser.
	message, err := json.Marshal(&webExtensionRoundTripRequest{
		Command: "roundtrip",
		ID:      id,
		Request: req,
	})
	if err != nil {
		panic(err)
	}
	outToBrowserChan <- message

	// Now wait for the browser to send the response back to us.
	// inFromBrowserLoop will find the proper channel by looking up the ID
	// in requestResponseMap.
	var resp responseSpec
	timeout := time.NewTimer(roundTripTimeout)
	select {
	case resp = <-responseSpecChan:
		timeout.Stop()
	case <-timeout.C:
		// But don't wait forever, so as to allow reclaiming memory in
		// case of a malfunction elsewhere.
		requestResponseMapLock.Lock()
		delete(requestResponseMap, id)
		requestResponseMapLock.Unlock()
		err = fmt.Errorf("timed out waiting for browser to reply")
	}
	return resp, err
}

// This is a responseSpec for errors that originate inside this program, as
// opposed to being relayed from the browser.
type errorResponseSpec struct {
	Error string `json:"error"`
}

// Handle a socket connection, which is used for one request–response roundtrip
// through the browser. Delegates the real work to roundTrip, which reads the
// requestSpec from the socket and sends it through the browser. Here, we wrap
// any error from roundTrip in an "error" response and send the response back on
// the socket.
func handleConn(conn net.Conn, outToBrowserChan chan<- []byte) error {
	defer conn.Close()

	resp, err := roundTrip(conn, outToBrowserChan)
	if err != nil {
		resp = &errorResponseSpec{Error: err.Error()}
	}

	// Encode the response send it back out over the socket.
	err = conn.SetWriteDeadline(time.Now().Add(localWriteTimeout))
	if err != nil {
		return err
	}
	return writeResponseSpec(conn, resp)
}

// Receive socket connections and dispatch them to handleConn.
func acceptLoop(ln net.Listener, outToBrowserChan chan<- []byte) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return err
		}
		go func() {
			err := handleConn(conn, outToBrowserChan)
			if err != nil {
				fmt.Fprintln(os.Stderr, "handling socket request:", err)
			}
		}()
	}
}

// Read messages from the browser over stdin, and send them (matching using the
// ID field) over the channel that corresponds to the original request. This is
// the only function allowed to read from stdin.
func inFromBrowserLoop() error {
	for {
		message, err := recvWebExtensionMessage(os.Stdin)
		if err != nil {
			return err
		}
		var resp webExtensionRoundTripResponse
		err = json.Unmarshal(message, &resp)
		if err != nil {
			return err
		}

		// Look up what channel (previously registered in
		// requestResponseMap by roundTrip) should receive the
		// response.
		requestResponseMapLock.Lock()
		responseSpecChan, ok := requestResponseMap[resp.ID]
		delete(requestResponseMap, resp.ID)
		requestResponseMapLock.Unlock()

		if !ok {
			// Either the browser made up an ID that we never sent
			// it, or (more likely) it took too long and roundTrip
			// stopped waiting. Just drop the response on the floor.
			continue
		}
		responseSpecChan <- resp.Response
		// Each socket Conn is good for one request–response exchange only.
		close(responseSpecChan)
	}
}

// Read messages from outToBrowserChan and send them to the browser over the
// stdout channel. This is the only function allowed to write to stdout.
func outToBrowserLoop(outToBrowserChan <-chan []byte) error {
	for message := range outToBrowserChan {
		err := sendWebExtensionMessage(os.Stdout, message)
		if err != nil {
			return err
		}
	}
	return nil
}

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer ln.Close()

	outToBrowserChan := make(chan []byte)
	signalChan := make(chan os.Signal)
	errChan := make(chan error)

	// Goroutine that handles new socket connections.
	go func() {
		errChan <- acceptLoop(ln, outToBrowserChan)
	}()

	// Goroutine that writes WebExtension messages to stdout.
	go func() {
		errChan <- outToBrowserLoop(outToBrowserChan)
	}()

	// Goroutine that reads WebExtension messages from stdin.
	go func() {
		err := inFromBrowserLoop()
		if err == io.EOF {
			// EOF is not an error.
			err = nil
		}
		errChan <- err
	}()

	// Tell the browser our listening socket address.
	message, err := json.Marshal(struct {
		Command string `json:"command"`
		Address string `json:"address"`
	}{
		Command: "report-address",
		Address: ln.Addr().String(),
	})
	if err != nil {
		panic(err)
	}
	outToBrowserChan <- message

	// We quit when we receive a SIGTERM, or when our stdin is closed, or
	// some irrecoverable error happens.
	// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging#Closing_the_native_app
	signal.Notify(signalChan, syscall.SIGTERM)
	select {
	case <-signalChan:
	case err := <-errChan:
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}
}
