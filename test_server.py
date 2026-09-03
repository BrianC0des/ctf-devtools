"""Mock CTF challenge server for testing."""
import http.server
import socketserver

PORT = 8888

HTML_CONTENT = """<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable CTF Challenge</title>
</head>
<body>
    <h1>Welcome to CTF Challenge</h1>
    <!-- Developer note: TODO remove debug key CTF{hidden_in_comment_flag} -->
    <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username" />
        <input type="password" name="password" placeholder="Password" />
        <input type="hidden" name="csrf_token" value="secr3t_csrf_t0k3n" />
        <input type="submit" value="Login" />
    </form>
    <script src="/static/bundle.js"></script>
</body>
</html>
"""

ROBOTS_TXT = """User-agent: *
Disallow: /super_secret_admin_panel
"""

ADMIN_CONTENT = """
<html><body><h1>Admin Portal</h1><p>Congratulations! Here is your flag: CTF{robots_txt_lead_to_victory}</p></body></html>
"""

DOT_ENV = """APP_ENV=production
SECRET_KEY=super_hardcoded_jwt_secret_key_123
FLAG=CTF{env_file_leakage_is_bad}
"""

class MockHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Werkzeug/2.3.0 Python/3.14")
            self.send_header("X-Powered-By", "Flask")
            self.end_headers()
            self.wfile.write(HTML_CONTENT.encode())
        elif self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(ROBOTS_TXT.encode())
        elif self.path == "/super_secret_admin_panel":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(ADMIN_CONTENT.encode())
        elif self.path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(DOT_ENV.encode())
        elif self.path == "/static/bundle.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b"console.log('App loaded'); const api_endpoint = '/api/v1/debug_panel';")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), MockHandler) as httpd:
        print(f"Serving test CTF challenge at http://127.0.0.1:{PORT}")
        httpd.serve_forever()
