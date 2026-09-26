from http.server import HTTPServer, BaseHTTPRequestHandler

class LoginHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length) 
        self.send_response(401)
        self.end_headers()
        self.wfile.write(b"Login failed")
    def log_message(self, format, *args):
        pass

server = HTTPServer(("0.0.0.0", 8000), LoginHandler)
print("Target login server running on http://0.0.0.0:8000")
server.serve_forever()