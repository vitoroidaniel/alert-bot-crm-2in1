"""
serve.py — Serves the CRM HTML file on port 3000.
This runs as a separate Railway service in the same project.
"""
import os
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

PORT = int(os.getenv("PORT", "3000"))

class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve index.html for all routes
        self.path = "/Kurtex_CRM.html"
        return super().do_GET()
    def log_message(self, *args):
        pass

os.chdir(Path(__file__).parent)
HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
