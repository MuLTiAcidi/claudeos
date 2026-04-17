#!/usr/bin/env python3
"""Simple webhook listener for blind SSRF testing"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, datetime

class Handler(BaseHTTPRequestHandler):
    def handle_request(self):
        ts = datetime.datetime.utcnow().isoformat()
        log = f"[{ts}] {self.command} {self.path} from {self.client_address[0]}\n"
        log += f"Headers: {dict(self.headers)}\n"
        
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode() if content_length else ''
        if body:
            log += f"Body: {body}\n"
        
        print(log)
        with open('/opt/claudeos-hunt/evidence/webhook-hits.log', 'a') as f:
            f.write(log + '---\n')
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"status": "captured"}).encode())
    
    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = handle_request

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 8888), Handler)
    print(f'Webhook listener on http://185.252.232.15:8888')
    server.serve_forever()
