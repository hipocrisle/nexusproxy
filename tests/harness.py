#!/usr/bin/env python3
"""Стенд: два веб-сервера и поддельный вышестоящий SOCKS5.
Всё локально — ни внешней сети, ни чужой инфраструктуры.
Поддельный прокси игнорирует запрошенный адрес и всегда ведёт на сервер
«PROXY», поэтому по ответу однозначно видно, каким путём пошёл запрос."""
import socket, threading, http.server, sys

def web(port, body):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())
        def log_message(self, *a): pass
    srv = http.server.HTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()

def fake_socks(port, target_port):
    def pipe(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d: break
                b.sendall(d)
        except OSError: pass
        finally:
            for s in (a, b):
                try: s.close()
                except OSError: pass
    def serve():
        ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind(("127.0.0.1", port)); ls.listen(64)
        while True:
            c, _ = ls.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    def handle(c):
        try:
            head = c.recv(2)
            nm = c.recv(head[1])
            c.sendall(b"\x05\x00")                      # без аутентификации
            req = c.recv(4)
            if req[3] == 1:   c.recv(4)
            elif req[3] == 4: c.recv(16)
            else:             c.recv(c.recv(1)[0])
            c.recv(2)
            c.sendall(b"\x05\x00\x00\x01" + b"\x00"*6)  # успех
            up = socket.create_connection(("127.0.0.1", target_port))
            threading.Thread(target=pipe, args=(c, up), daemon=True).start()
            pipe(up, c)
        except Exception:
            try: c.close()
            except OSError: pass
    threading.Thread(target=serve, daemon=True).start()

if __name__ == "__main__":
    web(9001, "DIRECT")
    web(9002, "PROXY")
    fake_socks(9050, 9002)
    print("стенд поднят: 9001=DIRECT 9002=PROXY 9050=поддельный вышестоящий SOCKS5", flush=True)
    threading.Event().wait()
