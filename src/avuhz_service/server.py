"""Loopback-only threaded WSGI server for local service certification."""
from socketserver import ThreadingMixIn
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


class BoundedRequestHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        # Request paths may contain authoritative IDs; the local adapter emits no access log.
        return None


def create_http_server(application, host="127.0.0.1", port=8080):
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("local service must bind loopback")
    return make_server(
        host, port, application,
        server_class=ThreadingWSGIServer,
        handler_class=BoundedRequestHandler,
    )


def serve(application, host="127.0.0.1", port=8080):
    server = create_http_server(application, host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
