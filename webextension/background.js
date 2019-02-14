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

function roundtrip(id, request) {
    // Process the incoming request spec and convert it into parameters to the
    // fetch API. Also enforce some restrictions on what kinds of requests we
    // are willing to make.
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

        // TODO: Host header
        // TODO: strip Origin header?
        // TODO: proxy
    } catch (error) {
        port.postMessage({id, response: {error: `request spec failed valiation: ${error.message}`}});
        return;
    }

    // Now actually do the request and send the result back to the native
    // process.
    fetch(url, init)
        .then(resp => resp.arrayBuffer().then(body => ({
            status: resp.status,
            body: base64_encode(body),
        })))
        // Convert any errors into an error response.
        .catch(error => ({error: error.message}))
        // Send the response (success or failure) back to the requester, tagged
        // with its ID.
        .then(response => port.postMessage({id, response}));
}

port.onMessage.addListener((message) => {
    switch (message.command) {
        case "roundtrip":
            roundtrip(message.id, message.request);
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
