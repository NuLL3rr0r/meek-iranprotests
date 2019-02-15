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

let port = browser.runtime.connectNative("meek.http.helper");

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

async function roundtrip(request) {
    // Process the incoming request spec and convert it into parameters to the
    // fetch API. Also enforce some restrictions on what kinds of requests we
    // are willing to make.
    // https://developer.mozilla.org/en-US/docs/Web/API/WindowOrWorkerGlobalScope/fetch#Parameters
    let url;
    let init = {};
    try {
        if (request.url == null) {
            throw new Error("missing \"url\"");
        }
        if (!(request.url.startsWith("http://") || request.url.startsWith("https://"))) {
            throw new Error("only http and https URLs are allowed");
        }
        url = request.url;

        if (request.method !== "POST") {
            throw new Error("only POST is allowed");
        }
        init.method = request.method;

        if (request.header != null) {
            init.headers = request.header;
        }

        if (request.body != null && request.body !== "") {
            init.body = base64_decode(request.body);
        }

        // Do not read nor write from the browser's HTTP cache.
        init.cache = "no-store";
        // Don't send cookies.
        init.credentials = "omit";
        // Don't follow redirects (we'll get resp.status:0 if there is one).
        init.redirect = "manual";

        // TODO: Host header
        // TODO: strip Origin header?
        // TODO: proxy
    } catch (error) {
        return {error: `request spec failed valiation: ${error.message}`};
    }

    // Now actually do the request and build a response object.
    try {
        let resp = await fetch(url, init);
        let body = await resp.arrayBuffer();
        return {status: resp.status, body: base64_encode(body)};
    } catch (error) {
        // Convert any errors into an error response.
        return {error: error.message};
    }
}

port.onMessage.addListener((message) => {
    switch (message.command) {
        case "roundtrip":
            // Do a roundtrip and send the result back to the native process.
            roundtrip(message.request)
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

port.onDisconnect.addListener((p) => {
    // https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/runtime/Port#Type
    // "Note that in Google Chrome port.error is not supported: instead, use
    // runtime.lastError to get the error message."
    if (p.error) {
        console.log(`${browser.runtime.id}: disconnected because of error: ${p.error.message}`);
    }
});
