"""`serve.py web` answers HTTP on 8080; `serve.py tls` answers HTTPS on 8443 with /certs/cert.pem and key.pem."""
import http.server
import ssl
import sys


class Page(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"service up"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if sys.argv[1] == "web":
    http.server.HTTPServer(("0.0.0.0", 8080), Page).serve_forever()
else:
    server = http.server.HTTPServer(("0.0.0.0", 8443), Page)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/cert.pem", "/certs/key.pem")
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
