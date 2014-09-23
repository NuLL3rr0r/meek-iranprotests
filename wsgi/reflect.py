# WSGI: https://www.python.org/dev/peps/pep-3333/

import httplib
import urlparse

FORWARD_URL = "http://meek.bamsoftware.com:7002/"
TIMEOUT = 20
BUFSIZ = 2048

REFLECTED_HEADER_FIELDS = [
    "Content-Type",
    "X-Session-Id",
]

# Limits a file-like object to reading only n bytes. Used to keep limit
# wsgi.input to the Content-Length, otherwise it blocks.
class LimitedReader(object):
    def __init__(self, f, n):
        self.f = f
        self.n = n

    def __getattr__(self, name):
        return getattr(self.f, name)

    def read(self, size=None):
        if self.n <= 0:
            return ""
        if size is not None and size > self.n:
            size = self.n
        data = self.f.read(size)
        self.n -= len(data)
        return data

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
        body = LimitedReader(environ["wsgi.input"], int(content_length))
        headers.append(("Content-Length", content_length))
    else:
        body = ""

    for name in REFLECTED_HEADER_FIELDS:
        value = get_header(environ, name)
        if value is not None:
            headers.append((name, value))
    headers = dict(headers)

    return method, url, body, headers

def make_conn(url):
    u = urlparse.urlsplit(url)
    create_connection = httplib.HTTPConnection
    if u.scheme == "https":
        create_connection = httplib.HTTPSConnection
    return create_connection(u.hostname, u.port, strict=True, timeout=TIMEOUT)

def make_request(conn, method, url, body, headers):
    u = urlparse.urlsplit(url)
    path = urlparse.urlunsplit(("", "", u.path, u.query, ""))
    conn.request(method, path, body, headers)
    return conn.getresponse()

def main(environ, start_response):
    try:
        method, url, body, headers = copy_request(environ, FORWARD_URL)
    except Exception, e:
        start_response("400 Bad Request", [("Content-Type", "text/plain; charset=utf-8")])
        yield "Bad Request"
        return
    try:
        conn = make_conn(url)
        resp = make_request(conn, method, url, body, headers)
    except Exception, e:
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

    conn.close()

if __name__ == "__main__":
    import wsgiref.simple_server
    server = wsgiref.simple_server.make_server("127.0.0.1", 8000, main)
    server.serve_forever()
