// meek-server is the server transport plugin for the meek pluggable transport.
// It acts as an HTTP server, keeps track of session ids, and forwards received
// data to a local OR port.
//
// Sample usage in torrc:
// 	ServerTransportListenAddr meek 0.0.0.0:443
// 	ServerTransportPlugin meek exec ./meek-server --acme-hostnames meek-server.example --acme-email admin@meek-server.example --log meek-server.log
// Using your own TLS certificate:
// 	ServerTransportListenAddr meek 0.0.0.0:8443
// 	ServerTransportPlugin meek exec ./meek-server --cert cert.pem --key key.pem --log meek-server.log
// Plain HTTP usage:
// 	ServerTransportListenAddr meek 0.0.0.0:8080
// 	ServerTransportPlugin meek exec ./meek-server --disable-tls --log meek-server.log
//
// The server runs in HTTPS mode by default, getting certificates from Let's
// Encrypt automatically. The server must be listening on port 443 for the
// automatic certificates to work. If you have your own certificate, use the
// --cert and --key options. Use --disable-tls option to run with plain HTTP.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"git.torproject.org/pluggable-transports/goptlib.git"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
)

const (
	programVersion = "0.28"

	ptMethodName = "meek"
	// Reject session ids shorter than this, as a weak defense against
	// client bugs that send an empty session id or something similarly
	// likely to collide.
	minSessionIDLength = 8
	// The largest request body we are willing to process, and the largest
	// chunk of data we'll send back in a response.
	maxPayloadLength = 0x10000
	// How long we try to read something back from the OR port before
	// returning the response.
	turnaroundTimeout = 10 * time.Millisecond
	// Passed as ReadTimeout and WriteTimeout when constructing the
	// http.Server.
	readWriteTimeout = 20 * time.Second
	// Cull unused session ids (with their corresponding OR port connection)
	// if we haven't seen any activity for this long.
	maxSessionStaleness = 120 * time.Second
	// How long to wait for ListenAndServe or ListenAndServeTLS to return an
	// error before deciding that it's not going to return.
	listenAndServeErrorTimeout = 100 * time.Millisecond
)

var ptInfo pt.ServerInfo

// When a connection handler starts, +1 is written to this channel; when it
// ends, -1 is written.
var handlerChan = make(chan int)

func httpBadRequest(w http.ResponseWriter) {
	http.Error(w, "Bad request.", http.StatusBadRequest)
}

func httpInternalServerError(w http.ResponseWriter) {
	http.Error(w, "Internal server error.", http.StatusInternalServerError)
}

// Every session id maps to an existing OR port connection, which we keep open
// between received requests. The first time we see a new session id, we create
// a new OR port connection.
type Session struct {
	Or       *net.TCPConn
	LastSeen time.Time
}

// Mark a session as having been seen just now.
func (session *Session) Touch() {
	session.LastSeen = time.Now()
}

// Is this session old enough to be culled?
func (session *Session) IsExpired() bool {
	return time.Since(session.LastSeen) > maxSessionStaleness
}

// There is one state per HTTP listener. In the usual case there is just one
// listener, so there is just one global state. State also serves as the http
// Handler.
type State struct {
	sessionMap map[string]*Session
	lock       sync.Mutex
}

func NewState() *State {
	state := new(State)
	state.sessionMap = make(map[string]*Session)
	return state
}

func (state *State) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	handlerChan <- 1
	defer func() {
		handlerChan <- -1
	}()

	switch req.Method {
	case "GET":
		state.Get(w, req)
	case "POST":
		state.Post(w, req)
	default:
		httpBadRequest(w)
	}
}

// Handle a GET request. This doesn't have any purpose apart from diagnostics.
func (state *State) Get(w http.ResponseWriter, req *http.Request) {
	if path.Clean(req.URL.Path) != "/" {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("I’m just a happy little web server.\n"))
}

// Get a string representing the original client address, if available, as a
// "host:port" string suitable to pass as the addr parameter to pt.DialOr. Never
// fails: if the original client address is not available, returns "". If the
// original client address is available, the returned port number is always 1.
func getUseraddr(req *http.Request) string {
	ip, err := originalClientIP(req)
	if err != nil {
		return ""
	}
	return net.JoinHostPort(ip.String(), "1")
}

// Look up a session by id, or create a new one (with its OR port connection) if
// it doesn't already exist.
func (state *State) GetSession(sessionID string, req *http.Request) (*Session, error) {
	state.lock.Lock()
	defer state.lock.Unlock()

	session := state.sessionMap[sessionID]
	if session == nil {
		// log.Printf("unknown session id %q; creating new session", sessionID)

		or, err := pt.DialOr(&ptInfo, getUseraddr(req), ptMethodName)
		if err != nil {
			return nil, err
		}
		session = &Session{Or: or}
		state.sessionMap[sessionID] = session
	}
	session.Touch()

	return session, nil
}

// scrubbedAddr is a phony net.Addr that returns "[scrubbed]" for all calls.
type scrubbedAddr struct{}

func (a scrubbedAddr) Network() string {
	return "[scrubbed]"
}
func (a scrubbedAddr) String() string {
	return "[scrubbed]"
}

// Replace the Addr in a net.OpError with "[scrubbed]" for logging.
func scrubError(err error) error {
	if operr, ok := err.(*net.OpError); ok {
		// net.OpError contains Op, Net, Addr, and a subsidiary Err. The
		// (Op, Net, Addr) part is responsible for error text prefixes
		// like "read tcp X.X.X.X:YYYY:". We want that information but
		// don't want to log the literal address.
		operr.Addr = scrubbedAddr{}
	}
	return err
}

// Feed the body of req into the OR port, and write any data read from the OR
// port back to w.
func transact(session *Session, w http.ResponseWriter, req *http.Request) error {
	body := http.MaxBytesReader(w, req.Body, maxPayloadLength+1)
	_, err := io.Copy(session.Or, body)
	if err != nil {
		return fmt.Errorf("error copying body to ORPort: %s", scrubError(err))
	}

	buf := make([]byte, maxPayloadLength)
	session.Or.SetReadDeadline(time.Now().Add(turnaroundTimeout))
	n, err := session.Or.Read(buf)
	if err != nil {
		if e, ok := err.(net.Error); !ok || !e.Timeout() {
			httpInternalServerError(w)
			// Don't scrub err here because it always refers to localhost.
			return fmt.Errorf("reading from ORPort: %s", err)
		}
	}
	// log.Printf("read %d bytes from ORPort: %q", n, buf[:n])
	// Set a Content-Type to prevent Go and the CDN from trying to guess.
	w.Header().Set("Content-Type", "application/octet-stream")
	n, err = w.Write(buf[:n])
	if err != nil {
		return fmt.Errorf("error writing to response: %s", scrubError(err))
	}
	// log.Printf("wrote %d bytes to response", n)
	return nil
}

// Handle a POST request. Look up the session id and then do a transaction.
func (state *State) Post(w http.ResponseWriter, req *http.Request) {
	sessionID := req.Header.Get("X-Session-Id")
	if len(sessionID) < minSessionIDLength {
		httpBadRequest(w)
		return
	}

	session, err := state.GetSession(sessionID, req)
	if err != nil {
		log.Print(err)
		httpInternalServerError(w)
		return
	}

	err = transact(session, w, req)
	if err != nil {
		log.Print(err)
		state.CloseSession(sessionID)
		return
	}
}

// Remove a session from the map and closes its corresponding OR port
// connection. Does nothing if the session id is not known.
func (state *State) CloseSession(sessionID string) {
	state.lock.Lock()
	defer state.lock.Unlock()
	// log.Printf("closing session %q", sessionID)
	session, ok := state.sessionMap[sessionID]
	if ok {
		session.Or.Close()
		delete(state.sessionMap, sessionID)
	}
}

// Loop forever, checking for expired sessions and removing them.
func (state *State) ExpireSessions() {
	for {
		time.Sleep(maxSessionStaleness / 2)
		state.lock.Lock()
		for sessionID, session := range state.sessionMap {
			if session.IsExpired() {
				// log.Printf("deleting expired session %q", sessionID)
				session.Or.Close()
				delete(state.sessionMap, sessionID)
			}
		}
		state.lock.Unlock()
	}
}

func initServer(addr *net.TCPAddr,
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error),
	listenAndServe func(*http.Server, chan<- error)) (*http.Server, error) {
	// We're not capable of listening on port 0 (i.e., an ephemeral port
	// unknown in advance). The reason is that while the net/http package
	// exposes ListenAndServe and ListenAndServeTLS, those functions never
	// return, so there's no opportunity to find out what the port number
	// is, in between the Listen and Serve steps.
	// https://groups.google.com/d/msg/Golang-nuts/3F1VRCCENp8/3hcayZiwYM8J
	if addr.Port == 0 {
		return nil, fmt.Errorf("cannot listen on port %d; configure a port using ServerTransportListenAddr", addr.Port)
	}

	state := NewState()
	go state.ExpireSessions()

	server := &http.Server{
		Addr:         addr.String(),
		Handler:      state,
		ReadTimeout:  readWriteTimeout,
		WriteTimeout: readWriteTimeout,
	}
	// We need to override server.TLSConfig.GetCertificate--but first
	// server.TLSConfig needs to be non-nil. If we just create our own new
	// &tls.Config, it will lack the default settings that the net/http
	// package sets up for things like HTTP/2. Therefore we first call
	// http2.ConfigureServer for its side effect of initializing
	// server.TLSConfig properly. An alternative would be to make a dummy
	// net.Listener, call Serve on it, and let it return.
	// https://github.com/golang/go/issues/16588#issuecomment-237386446
	err := http2.ConfigureServer(server, nil)
	if err != nil {
		return server, err
	}
	server.TLSConfig.GetCertificate = getCertificate

	// Another unfortunate effect of the inseparable net/http ListenAndServe
	// is that we can't check for Listen errors like "permission denied" and
	// "address already in use" without potentially entering the infinite
	// loop of Serve. The hack we apply here is to wait a short time,
	// listenAndServeErrorTimeout, to see if an error is returned (because
	// it's better if the error message goes to the tor log through
	// SMETHOD-ERROR than if it only goes to the meek-server log).
	errChan := make(chan error)
	go listenAndServe(server, errChan)
	select {
	case err = <-errChan:
		break
	case <-time.After(listenAndServeErrorTimeout):
		break
	}

	return server, err
}

func startServer(addr *net.TCPAddr) (*http.Server, error) {
	return initServer(addr, nil, func(server *http.Server, errChan chan<- error) {
		log.Printf("listening with plain HTTP on %s", addr)
		err := server.ListenAndServe()
		if err != nil {
			log.Printf("Error in ListenAndServe: %s", err)
		}
		errChan <- err
	})
}

func startServerTLS(addr *net.TCPAddr, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)) (*http.Server, error) {
	return initServer(addr, getCertificate, func(server *http.Server, errChan chan<- error) {
		log.Printf("listening with HTTPS on %s", addr)
		err := server.ListenAndServeTLS("", "")
		if err != nil {
			log.Printf("Error in ListenAndServeTLS: %s", err)
		}
		errChan <- err
	})
}

func getCertificateCacheDir() (string, error) {
	stateDir, err := pt.MakeStateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(stateDir, "meek-certificate-cache"), nil
}

func main() {
	var acmeEmail string
	var acmeHostnamesCommas string
	var disableTLS bool
	var certFilename, keyFilename string
	var logFilename string
	var port int

	flag.StringVar(&acmeEmail, "acme-email", "", "optional contact email for Let's Encrypt notifications")
	flag.StringVar(&acmeHostnamesCommas, "acme-hostnames", "", "comma-separated hostnames for automatic TLS certificate")
	flag.BoolVar(&disableTLS, "disable-tls", false, "don't use HTTPS")
	flag.StringVar(&certFilename, "cert", "", "TLS certificate file")
	flag.StringVar(&keyFilename, "key", "", "TLS private key file")
	flag.StringVar(&logFilename, "log", "", "name of log file")
	flag.IntVar(&port, "port", 0, "port to listen on")
	flag.Parse()

	var err error
	ptInfo, err = pt.ServerSetup(nil)
	if err != nil {
		log.Fatalf("error in ServerSetup: %s", err)
	}

	log.SetFlags(log.LstdFlags | log.LUTC)
	if logFilename != "" {
		f, err := os.OpenFile(logFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			// If we fail to open the log, emit a message that will
			// appear in tor's log.
			pt.SmethodError(ptMethodName, fmt.Sprintf("error opening log file: %s", err))
			log.Fatalf("error opening log file: %s", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	// Handle the various ways of setting up TLS. The legal configurations
	// are:
	//   --acme-hostnames (with optional --acme-email)
	//   --cert and --key together
	//   --disable-tls
	// The outputs of this block of code are the disableTLS,
	// need443Listener, and getCertificate variables.
	var need443Listener = false
	var getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if disableTLS {
		if acmeEmail != "" || acmeHostnamesCommas != "" || certFilename != "" || keyFilename != "" {
			log.Fatalf("The --acme-email, --acme-hostnames, --cert, and --key options are not allowed with --disable-tls.")
		}
	} else if certFilename != "" && keyFilename != "" {
		if acmeEmail != "" || acmeHostnamesCommas != "" {
			log.Fatalf("The --cert and --key options are not allowed with --acme-email or --acme-hostnames.")
		}
		ctx, err := newCertContext(certFilename, keyFilename)
		if err != nil {
			log.Fatal(err)
		}
		getCertificate = ctx.GetCertificate
	} else if acmeHostnamesCommas != "" {
		acmeHostnames := strings.Split(acmeHostnamesCommas, ",")
		log.Printf("ACME hostnames: %q", acmeHostnames)

		// The ACME responder only works when it is running on port 443.
		// https://letsencrypt.github.io/acme-spec/#domain-validation-with-server-name-indication-dvsni
		need443Listener = true

		var cache autocert.Cache
		cacheDir, err := getCertificateCacheDir()
		if err == nil {
			log.Printf("caching ACME certificates in directory %q", cacheDir)
			cache = autocert.DirCache(cacheDir)
		} else {
			log.Printf("disabling ACME certificate cache: %s", err)
		}

		certManager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(acmeHostnames...),
			Email:      acmeEmail,
			Cache:      cache,
		}
		getCertificate = certManager.GetCertificate
	} else {
		log.Fatalf("You must use either --acme-hostnames, or --cert and --key.")
	}

	log.Printf("starting version %s (%s)", programVersion, runtime.Version())
	servers := make([]*http.Server, 0)
	have443Listener := false
	for _, bindaddr := range ptInfo.Bindaddrs {
		if port != 0 {
			bindaddr.Addr.Port = port
		}
		switch bindaddr.MethodName {
		case ptMethodName:
			var server *http.Server
			if disableTLS {
				server, err = startServer(bindaddr.Addr)
			} else {
				if bindaddr.Addr.Port == 443 {
					have443Listener = true
				}
				server, err = startServerTLS(bindaddr.Addr, getCertificate)
			}
			if err != nil {
				pt.SmethodError(bindaddr.MethodName, err.Error())
				break
			}
			pt.Smethod(bindaddr.MethodName, bindaddr.Addr)
			servers = append(servers, server)
		default:
			pt.SmethodError(bindaddr.MethodName, "no such method")
		}
	}
	pt.SmethodsDone()

	// Emit a warning if we're using ACME certificates and don't have a 443
	// listener. Don't quit, in case the user has made other provisions for
	// forwarding port 443.
	if need443Listener && !have443Listener {
		log.Printf("warning: the --acme-hostnames option requires one of the bindaddrs to be on port 443.")
	}

	var numHandlers int = 0
	var sig os.Signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Wait for first signal.
	sig = nil
	for sig == nil {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
			log.Printf("got signal %s", sig)
		}
	}
	/*
		// Not supported until go1.8.
		for _, server := range servers {
			server.Close()
		}
	*/

	if sig == syscall.SIGTERM {
		log.Printf("done")
		return
	}

	// Wait for second signal or no more handlers.
	sig = nil
	for sig == nil && numHandlers != 0 {
		select {
		case n := <-handlerChan:
			numHandlers += n
		case sig = <-sigChan:
			log.Printf("got second signal %s", sig)
		}
	}

	log.Printf("done")
}
