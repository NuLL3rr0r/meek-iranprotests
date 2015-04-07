# WSGI: https://www.python.org/dev/peps/pep-3333/

import httplib
import urlparse
import threading

FORWARD_URL = "https://meek.bamsoftware.com/"
TIMEOUT = 20
BUFSIZ = 2048
MAX_REQUEST_LENGTH = 0x10000

REFLECTED_HEADER_FIELDS = [
    "Content-Type",
    "X-Session-Id",
]

# Join two URL paths.
def path_join(a, b):
    if a.endswith("/"):
        a = a[:-1]
    if not b.startswith("/"):
        b = "/" + b
    return a + b

def get_header(environ, name):
    if name.lower() == "content-type":
        envar = "CONTENT_TYPE"
    elif name.lower() == "content-length":
        envar = "CONTENT_LENGTH"
    else:
        envar = "HTTP_" + name.replace("-", "_").upper()
    return environ.get(envar)

def copy_request(environ, url):
    method = environ["REQUEST_METHOD"]

    # Append PATH_INFO to the path of url.
    u = urlparse.urlsplit(url)
    path = path_join(u.path, environ["PATH_INFO"])
    url = urlparse.urlunsplit((u.scheme, u.netloc, path, u.query, u.fragment))

    headers = []

    content_length = environ.get("CONTENT_LENGTH")
    if content_length:
        content_length = int(content_length)
        # We read the whole response body (and limit its length). Normally we
        # would just pass environ["wsgi.input"] as the body to
        # HTTPSConnection.request. But make_request may need to try the request
        # twice, in which case it needs to send the same body the second time.
        if content_length > MAX_REQUEST_LENGTH:
            raise ValueError("Content-Length too large: %d" % content_length)
        body = environ["wsgi.input"].read(content_length)
    else:
        body = ""

    for name in REFLECTED_HEADER_FIELDS:
        value = get_header(environ, name)
        if value is not None:
            headers.append((name, value))
    headers = dict(headers)

    return method, url, body, headers

# We want to reuse persistent HTTPSConnections. If we don't then every request
# will start a branch new TCP and TLS connection, leading to increased latency
# and high CPU use on meek-server. A pool just locks connections so only one
# thread can use a connection at a time. If the connection is still good after
# use, then the caller should put it back by calling restore_conn.
class ConnectionPool(object):
    def __init__(self, url):
        self.url = urlparse.urlsplit(url)
        self.conns = []
        self.lock = threading.RLock()

    def new_conn(self):
        create_connection = httplib.HTTPConnection
        if self.url.scheme == "https":
            create_connection = httplib.HTTPSConnection
        return create_connection(self.url.hostname, self.url.port, strict=True, timeout=TIMEOUT)

    def get_conn(self):
        with self.lock:
            try:
                return self.conns.pop(0)
            except IndexError:
                pass
        return self.new_conn()

    def restore_conn(self, conn):
        with self.lock:
            self.conns.append(conn)

def make_request(conn, method, url, body, headers):
    u = urlparse.urlsplit(url)
    path = urlparse.urlunsplit(("", "", u.path, u.query, ""))
    conn.request(method, path, body, headers)
    try:
        return conn.getresponse()
    except httplib.BadStatusLine, e:
        if e.message != "":
            raise
        # There's a very common error with httplib persistent connections. If
        # you let a connection idle until it times out, then issue a request,
        # you will get a BadStatusLine("") exception, not when the request is
        # sent, but when getresponse tries to read from a closed socket. When
        # that happens, we reinitialize the connection by first closing it,
        # which will cause a new TCP and TLS handshake to happen for the next
        # request.
        conn.close()
        conn.request(method, path, body, headers)
        return conn.getresponse()

pool = ConnectionPool(FORWARD_URL)

def main(environ, start_response):
    try:
        method, url, body, headers = copy_request(environ, FORWARD_URL)
    except Exception, e:
        start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
        yield "Bad Request"
        return

    try:
        conn = pool.get_conn()
        resp = make_request(conn, method, url, body, headers)
    except Exception, e:
        # Discard conn.
        start_response("500 Internal Server Error", [("Content-Type", "text/plain; charset=utf-8")])
        yield "Internal Server Error"
        return

    headers = []
    for name in REFLECTED_HEADER_FIELDS:
        value = resp.getheader(name)
        if value is not None:
            headers.append((name, value))

    start_response("%d %s" % (resp.status, resp.reason), headers)
    while True:
        data = resp.read(BUFSIZ)
        if not data:
            break
        yield data

    resp.close()
    pool.restore_conn(conn)

if __name__ == "__main__":
    import wsgiref.simple_server
    server = wsgiref.simple_server.make_server("127.0.0.1", 8000, main)
    server.serve_forever()
