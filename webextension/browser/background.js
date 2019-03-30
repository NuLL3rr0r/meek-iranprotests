// This program is the browser part of the meek-http-helper WebExtension. Its
// purpose is to receive and execute commands from the native part. It
// understands two commands: "report-address" and "roundtrip".
//
//
// {
//   "command": "report-address",
//   "address": "127.0.0.1:XXXX"
// }
// The "report-address" command causes the extension to print to a line to
// stdout:
//   meek-http-helper: listen 127.0.0.1:XXXX
// meek-client looks for this line to find out where the helper is listening.
// For this to work, you must set the pref browser.dom.window.dump.enabled.
//
//
// {
//   "command": "roundtrip",
//   "id": "...ID..."
//   "request": {
//     "method": "POST",
//     "url": "https://allowed.example/",
//     "header": {
//       "Host": "forbidden.example",
//       "X-Session-Id": ...,
//       ...
//     },
//     "proxy": {
//       "type": "http",
//       "host": "proxy.example",
//       "port": 8080
//     },
//     "body": "...base64..."
//   }
// }
// The "roundtrip" command causes the extension to make an HTTP request
// according to the given specification. It then sends a response back to the
// native part:
// {
//   "id": "...ID...",
//   "response": {
//     "status": 200,
//     "body": "...base64..."
//   }
// }
// Or, if an error occurred:
// {
//   "id": "...ID...",
//   "response": {
//     "error": "...error message..."
//   }
// }
// The "id" field in the response will be the same as the one in the request,
// because that is what enables the native part to match up requests and
// responses.

// Decode a base64-encoded string into an ArrayBuffer.
function base64_decode(enc_str) {
    // First step is to decode the base64. atob returns a byte string; i.e., a
    // string of 16-bit characters, each of whose character codes is restricted
    // to the range 0x00–0xff.
    let dec_str = atob(enc_str);
    // Next, copy those character codes into an array of 8-bit elements.
    let dec_array = new Uint8Array(dec_str.length);
    for (let i = 0; i < dec_str.length; i++) {
        dec_array[i] = dec_str.charCodeAt(i);
    }
    return dec_array.buffer;
}

// Encode an ArrayBuffer into a base64-encoded string.
function base64_encode(dec_buf) {
    let dec_array = new Uint8Array(dec_buf);
    // Copy the elements of the array into a new byte string.
    let dec_str = String.fromCharCode(...dec_array);
    // base64-encode the byte string.
    return btoa(dec_str);
}

// Return a proxy.ProxyInfo according to the given specification.
//
// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/proxy/ProxyInfo
// The specification may look like:
//   undefined
//   {"type": "http", "host": "example.com", "port": 8080}
//   {"type": "socks5", "host": "example.com", "port": 1080}
//   {"type": "socks4a", "host": "example.com", "port": 1080}
function makeProxyInfo(spec) {
    if (spec == null) {
        return {type: "direct"};
    }
    switch (spec.type) {
        case "http":
            return {type: "http", host: spec.host, port: spec.port};
        // What tor calls "socks5", WebExtension calls "socks".
        case "socks5":
            return {type: "socks", host: spec.host, port: spec.port, proxyDNS: true};
        // What tor calls "socks4a", WebExtension calls "socks4".
        case "socks4a":
            return {type: "socks4", host: spec.host, port: spec.port, proxyDNS: true};
    };
    throw new Error(`unknown proxy type ${spec.type}`);
}

// A Mutex's lock function returns a promise that resolves to a function which,
// when called, allows the next call to lock to proceed.
// https://stackoverflow.com/a/51086893
function Mutex() {
    // Initially unlocked.
    let p = Promise.resolve();
    this.lock = function() {
        let old_p = p;
        let unlock;
        // Make a new promise for the *next* caller to wait on. Copy the new
        // promise's resolve function into the outer scope as "unlock".
        p = new Promise(resolve => unlock = resolve);
        // The caller gets a promise that allows them to unlock the *next*
        // caller.
        return old_p.then(() => unlock);
    }
}

// Enforce exclusive access to onBeforeSendHeaders and onRequest listeners.
const headersMutex = new Mutex();
const proxyMutex = new Mutex();

async function roundtrip(params) {
    // Process the incoming request parameters and convert them into a Request.
    // https://developer.mozilla.org/en-US/docs/Web/API/Request/Request#Parameters
    const input = params.url;
    const init = {
        method: params.method,
        body: params.body != null ? base64_decode(params.body) : undefined,
        // headers will get further treatment below in headersFn.
        headers: params.header != null ? params.header : {},
        // Do not read nor write from the browser's HTTP cache.
        cache: "no-store",
        // Don't send cookies.
        credentials: "omit",
        // Don't follow redirects (we'll get resp.status:0 if there is one).
        redirect: "manual",
    };

    // Also enforce restrictions on what kinds of requests we are willing to
    // make.
    if (input == null) {
        throw new Error("request spec failed validation: missing \"url\"");
    }
    if (!(input.startsWith("http://") || input.startsWith("https://"))) {
        throw new Error("request spec failed validation: only http and https URLs are allowed");
    }
    if (init.method !== "POST") {
        throw new Error("request spec failed validation: only POST is allowed");
    }
    const request = new Request(input, init);

    // We need to use a webRequest.onBeforeSendHeaders listener to override
    // certain header fields, including Host (creating a Request with them in
    // init.headers does not work). But onBeforeSendHeaders is a global setting
    // (applies to all requests) and we need to be able to set different headers
    // per request. We make it so that any onBeforeSendHeaders listener is only
    // used for a single request, by acquiring a lock here and releasing it
    // within the listener itself. The lock is acquired and released before any
    // network communication happens; i.e., it's fast.
    const headersUnlock = await headersMutex.lock();
    let headersCalled = false;
    function headersFn(details) {
        try {
            // Sanity assertion: per-request listeners are called at most once.
            if (headersCalled) {
                throw new Error("headersFn called more than once");
            }
            headersCalled = true;

            let removals = new Map();
            for (let name of Object.keys(init.headers)) {
                removals.set(name.toLowerCase());
            }
            // Also remove some unnecessary or potentially tracking-enabling headers.
            for (let name of ["Accept", "Accept-Language", "Cookie", "Origin", "User-Agent"]) {
                removals.set(name.toLowerCase());
            }
            let requestHeaders = details.requestHeaders.filter(header => !removals.has(header.name.toLowerCase()));
            // Append the requested headers in array form.
            // https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/HttpHeaders
            for (let [name, value] of Object.entries(init.headers)) {
                requestHeaders.push({name, value});
            }
            return {requestHeaders};
        } catch (error) {
            // In case of any error in the code above, play it safe and cancel
            // the request.
            console.log(`${browser.runtime.id}: error in onBeforeSendHeaders: ${error.message}`);
            return {cancel: true};
        } finally {
            // Now that the listener has been called, remove it and release the
            // lock to allow the next request to set a different listener.
            browser.webRequest.onBeforeSendHeaders.removeListener(headersFn);
            headersUnlock();
        }
    }

    // Similarly, for controlling the proxy for each request, we set a
    // proxy.onRequest listener, use it for one request, then remove it.
    const proxyUnlock = await proxyMutex.lock();
    let proxyCalled = false;
    // async to make exceptions visible to proxy.onError.
    // https://bugzilla.mozilla.org/show_bug.cgi?id=1528873#c1
    // https://bugzilla.mozilla.org/show_bug.cgi?id=1533505
    async function proxyFn(details) {
        try {
            // Sanity assertion: per-request listeners are called at most once.
            if (proxyCalled) {
                throw new Error("proxyFn called more than once");
            }
            proxyCalled = true;

            return makeProxyInfo(params.proxy);
        } finally {
            browser.proxy.onRequest.removeListener(proxyFn);
            proxyUnlock();
        }
    }

    try {
        // Set a listener that overrides the headers for this request.
        // https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/onBeforeSendHeaders
        browser.webRequest.onBeforeSendHeaders.addListener(
            headersFn,
            {urls: ["http://*/*", "https://*/*"]},
            ["blocking", "requestHeaders"]
        );
        // Set a listener that overrides the proxy for this request.
        // https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/proxy/onRequest
        browser.proxy.onRequest.addListener(
            proxyFn,
            {urls: ["http://*/*", "https://*/*"]}
        );

        // Now actually do the request and build a response object.
        let response = await fetch(request);
        return {
            status: response.status,
            body: base64_encode(await response.arrayBuffer()),
        };
    } finally {
        // With certain errors (e.g. an invalid URL), our onBeforeSendHeaders
        // and onRequest listeners may never get called, and therefore never
        // release their locks. Ensure that locks are released and listeners
        // removed in any case. It's safe to release a lock or remove a listener
        // more than once.
        browser.webRequest.onBeforeSendHeaders.removeListener(headersFn);
        headersUnlock();
        browser.proxy.onRequest.removeListener(proxyFn);
        proxyUnlock();
    }
}

// If an error occurs in a proxy.onRequest listener (for instance if a ProxyInfo
// field is missing or invalid), the browser will ignore the proxy and just
// connect directly. It will, however, call proxy.onError listeners. Register a
// static proxy.onError listener that sets a global flag if an error ever
// occurs; and a static browser.onBeforeRequest listener which checks the flag
// and cancels every request if it is set. We could be less severe here (we
// probably only need to cancel the *next* request that occurs after a proxy
// error), but this setup is meant to be a fail-closed safety net for what is
// essentially a "can't happen" state under correct configuration. Note that
// proxy.onError doesn't get called for transient errors like a failure to
// connect to the proxy, only for nonsensical ProxyInfo configurations.
// https://bugzilla.mozilla.org/show_bug.cgi?id=1533509
// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/proxy/onError
let proxyError = null;
browser.proxy.onError.addListener(error => {
    console.log(`proxy error, disabling: ${error.message}`);
    proxyError = error;
});
browser.webRequest.onBeforeRequest.addListener(
    details => ({cancel: proxyError != null}),
    {urls: ["http://*/*", "https://*/*"]},
    ["blocking"]
);

// Set a top-level error logger for webRequest, to aid debugging.
browser.webRequest.onErrorOccurred.addListener(
    details => console.log(`${browser.runtime.id}: webRequest error:`, details),
    {urls: ["http://*/*", "https://*/*"]}
);

// Allow unproxied DNS, working around a Tor Browser patch: https://bugs.torproject.org/11183#comment:6.
// We manually override the proxy for every request, and in makeProxyInfo we set
// proxyDNS:true wherever necessary, so name resolution uses the proxy despite
// this pref.
//
// In Tor Browser, the pref changes here are only temporary. The
// meek-http-helper profile has a user.js file that sets a default blackhole
// proxy, as a safety feature in case something goes wrong running the headless
// browser.
//
// We only care to set proxyDNS here, but must additionally set proxyType until
// Firefox 63 because of a bug.
// https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/proxy/settings
// https://bugzilla.mozilla.org/show_bug.cgi?id=1487121
browser.proxy.settings.set({value: {proxyType: "system", proxyDNS: false}});

// Connect to our native process.
const port = browser.runtime.connectNative("meek.http.helper");

port.onMessage.addListener(message => {
    switch (message.command) {
        case "roundtrip":
            // Do a roundtrip and send the result back to the native process.
            roundtrip(message.request)
                // Convert any error into an "error" response.
                .catch(error => ({error: error.message}))
                .then(response => port.postMessage({id: message.id, response}));
            break;
        case "report-address":
            // Tell meek-client where our subprocess (the one that actually
            // opens a socket) is listening. For the dump call to have any
            // effect, the pref browser.dom.window.dump.enabled must be true.
            // This output is supposed to be line-oriented, so ignore it if the
            // address from the native part contains a newline.
            if (message.address != null && message.address.indexOf("\n") == -1) {
                dump(`meek-http-helper: listen ${message.address}\n`);
            }
            break;
        default:
            console.log(`${browser.runtime.id}: received unknown command: ${message.command}`);
    }
});

port.onDisconnect.addListener(p => {
    // https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/runtime/Port#Type
    // "Note that in Google Chrome port.error is not supported: instead, use
    // runtime.lastError to get the error message."
    let error = p.error || browser.runtime.lastError;
    if (error) {
        console.log(`${browser.runtime.id}: disconnected because of error: ${error.message}`);
    }
});
