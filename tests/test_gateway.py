import asyncio
import base64
import http.server
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UUID_STR = "11111111-2222-3333-4444-555555555555"
UUID_BYTES = bytes.fromhex(UUID_STR.replace("-", ""))
GATE = 18080
TCPP = 19443
HTTP_T = 18081
UDP_T = 18082
HELLO = b"HELLO-FROM-TARGET"
results = []


def check(name, cond, info=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + ((" | " + str(info)[:200]) if not cond else ""))


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(HELLO)))
        self.end_headers()
        self.wfile.write(HELLO)

    def log_message(self, *a):
        pass


def udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", UDP_T))
    while True:
        d, a = s.recvfrom(65535)
        s.sendto(d, a)


def vless_hdr(cmd, addr, port, uuid=UUID_BYTES):
    if addr.count(".") == 3 and addr.replace(".", "").isdigit():
        at = bytes([1]) + bytes(int(x) for x in addr.split("."))
    else:
        at = bytes([2]) + bytes([len(addr)]) + addr.encode()
    return b"\x00" + uuid + b"\x00" + bytes([cmd]) + port.to_bytes(2, "big") + at


def recv_all(sock, timeout=5, until=None):
    sock.settimeout(timeout)
    data = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        if until and until in data:
            break
    return data


def ws_handshake(port, path):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        "GET %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ) % (path, port, key)
    s.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        c = s.recv(4096)
        if not c:
            raise RuntimeError("closed during handshake")
        buf += c
    head, _, rest = buf.partition(b"\r\n\r\n")
    assert b"101" in head.split(b"\r\n")[0], head
    return s, rest


def ws_send(s, payload):
    mask = os.urandom(4)
    ln = len(payload)
    h = bytes([0x82])
    if ln < 126:
        h += bytes([0x80 | ln])
    elif ln < 65536:
        h += bytes([0x80 | 126]) + struct.pack(">H", ln)
    else:
        h += bytes([0x80 | 127]) + struct.pack(">Q", ln)
    s.sendall(h + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))


def ws_recv_all(s, rest, timeout=5, until=None):
    buf = bytearray(rest)
    data = bytearray()
    s.settimeout(timeout)
    end = time.time() + timeout
    while time.time() < end:
        progressed = False
        while len(buf) >= 2:
            op = buf[0] & 0x0F
            ln = buf[1] & 0x7F
            pos = 2
            if ln == 126:
                if len(buf) < 4:
                    break
                ln = struct.unpack(">H", bytes(buf[2:4]))[0]
                pos = 4
            elif ln == 127:
                if len(buf) < 10:
                    break
                ln = struct.unpack(">Q", bytes(buf[2:10]))[0]
                pos = 10
            if buf[1] & 0x80:
                if len(buf) < pos + 4:
                    break
                pos += 4
            if len(buf) < pos + ln:
                break
            del buf[:pos]
            payload = bytes(buf[:ln])
            del buf[:ln]
            progressed = True
            if op in (0x0, 0x1, 0x2):
                data += payload
            elif op == 0x8:
                return bytes(data)
        if until and until in data:
            break
        if progressed:
            continue
        try:
            c = s.recv(65536)
        except socket.timeout:
            break
        if not c:
            break
        buf += c
    return bytes(data)


def main():
    httpd = http.server.HTTPServer(("127.0.0.1", HTTP_T), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    threading.Thread(target=udp_echo, daemon=True).start()

    tmp = tempfile.mkdtemp()
    env = dict(os.environ, UUID=UUID_STR, PORT=str(GATE), TCP_PORT=str(TCPP),
               TCP_PUBLIC_PORT=str(TCPP), DATA_DIR=tmp, TAG="TESTTAG")
    logf = open(os.path.join(tmp, "gw.log"), "w")
    gw = subprocess.Popen([sys.executable, "main.py"], cwd=ROOT, env=env,
                          stdout=logf, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", GATE), timeout=1).close()
                socket.create_connection(("127.0.0.1", TCPP), timeout=1).close()
                break
            except OSError:
                time.sleep(0.2)
        else:
            print(open(os.path.join(tmp, "gw.log")).read())
            raise RuntimeError("gateway did not start")

        # --- text endpoints ---
        def get(path):
            r = urllib.request.urlopen("http://127.0.0.1:%d%s" % (GATE, path), timeout=5)
            return r.status, r.read().decode()

        st, body = get("/sub")
        lines = [l for l in body.strip().split("\n") if l]
        check("sub status 200", st == 200)
        check("sub has two links", len(lines) == 2, body)
        check("link1 is ws", lines and lines[0].startswith("vless://") and "type=ws" in lines[0], body)
        check("link1 uuid", UUID_STR in (lines[0] if lines else ""), body)
        check("link2 is tcp 9443", len(lines) > 1 and (":" + str(TCPP) + "?") in lines[1] and "type=tcp" in lines[1], body)
        check("tag in links", "TESTTAG" in body, body)
        st2, body2 = get("/")
        check("/ equals /sub", body2 == body)
        st3, body3 = get("/healthz")
        check("healthz", st3 == 200 and body3 == "ok")
        try:
            urllib.request.urlopen("http://127.0.0.1:%d/nope" % GATE, timeout=5)
            check("404", False)
        except urllib.error.HTTPError as e:
            check("404", e.code == 404)

        # --- raw vless tcp via dedicated port, domain addr ---
        s = socket.create_connection(("127.0.0.1", TCPP), timeout=5)
        s.sendall(vless_hdr(1, "127.0.0.1", HTTP_T) +
                  b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = recv_all(s, until=HELLO)
        s.close()
        check("tcp vless (domain addr)", data.startswith(b"\x00\x00") and HELLO in data, data[:80])

        # --- raw vless tcp via main port (sniff), ipv4 addr ---
        s = socket.create_connection(("127.0.0.1", GATE), timeout=5)
        s.sendall(vless_hdr(1, "127.0.0.1", HTTP_T) +
                  b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = recv_all(s, until=HELLO)
        s.close()
        check("tcp vless via sniff port (ipv4 addr)", data.startswith(b"\x00\x00") and HELLO in data, data[:80])

        # --- bad uuid rejected ---
        s = socket.create_connection(("127.0.0.1", TCPP), timeout=5)
        s.sendall(vless_hdr(1, "127.0.0.1", HTTP_T, uuid=b"\x00" * 16) +
                  b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        data = recv_all(s, timeout=3)
        s.close()
        check("bad uuid rejected", HELLO not in data and b"\x00\x00" not in data, data[:80])

        # --- vless over websocket ---
        s, rest = ws_handshake(GATE, "/ws")
        ws_send(s, vless_hdr(1, "127.0.0.1", HTTP_T) +
                b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = ws_recv_all(s, rest, until=HELLO)
        s.close()
        check("ws vless", data.startswith(b"\x00\x00") and HELLO in data, data[:80])

        # --- udp over raw tcp transport ---
        s = socket.create_connection(("127.0.0.1", TCPP), timeout=5)
        s.sendall(vless_hdr(2, "127.0.0.1", UDP_T) + (8).to_bytes(2, "big") + b"ping-udp")
        data = recv_all(s, until=b"ping-udp")
        s.close()
        check("udp vless", data.startswith(b"\x00\x00") and data[2:] == (8).to_bytes(2, "big") + b"ping-udp", data[:40])

        # --- gateway still alive ---
        st, _ = get("/healthz")
        check("alive after tests", st == 200)

        # --- admin panel ---
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        opener = urllib.request.build_opener(NoRedirect)

        def req(path, data=None, cookie=None, method=None):
            r = urllib.request.Request("http://127.0.0.1:%d%s" % (GATE, path),
                                       data=data, method=method)
            if cookie:
                r.add_header("Cookie", cookie)
            try:
                resp = opener.open(r, timeout=5)
                return resp.status, dict(resp.headers), resp.read().decode()
            except urllib.error.HTTPError as e:
                return e.code, dict(e.headers), e.read().decode()

        st, hdrs, body = req("/admin")
        check("admin requires login", st == 200 and "password" in body.lower(), (st, body[:120]))

        st, hdrs, body = req("/admin/login", data=b"password=wrong", method="POST")
        check("admin wrong password", st == 401, (st, body[:120]))

        st, hdrs, body = req("/admin/login", data=b"password=admin", method="POST")
        loc = hdrs.get("Location", "")
        setc = hdrs.get("Set-Cookie", "")
        check("admin login ok", st == 302 and loc == "/admin" and "gwa=" in setc, (st, loc, setc[:80]))
        cookie = "gwa=" + setc.split("gwa=")[1].split(";")[0]

        st, hdrs, body = req("/admin", cookie=cookie)
        check("admin page", st == 200 and "tcp host" in body.lower(), (st, body[:120]))

        st, hdrs, body = req("/admin/save", data=b"host=127.0.0.1&port=19999",
                             cookie=cookie, method="POST")
        check("admin save redirects", st == 302, (st, body[:80]))
        st, body = get("/sub")
        check("admin save affects sub", ":19999?" in body, body)

        st, hdrs, body = req("/admin/save", data=b"host=127.0.0.1:18081&port=9999",
                             cookie=cookie, method="POST")
        check("admin save host:port", st == 302, (st, body[:80]))
        st, body = get("/sub")
        check("colon host splits port", ":18081?" in body and ":9999?" not in body, body)

        st, hdrs, body = req("/admin/reset", data=b"", cookie=cookie, method="POST")
        check("admin reset", st == 302, (st, body[:80]))
        st, body = get("/sub")
        check("reset back to auto", ":19443?" in body, body)

        st, hdrs, body = req("/admin/test", data=b"host=127.0.0.1&port=%d" % TCPP,
                             cookie=cookie, method="POST")
        check("admin test button", st == 200 and "connect OK" in body, body[:200])

    finally:
        gw.terminate()
        try:
            gw.wait(3)
        except Exception:
            gw.kill()
        log = open(os.path.join(tmp, "gw.log")).read()
        print("---- gateway log ----")
        print(log[:3000])

    failed = [n for n, ok in results if not ok]
    print("\n%d/%d passed" % (len(results) - len(failed), len(results)))
    if failed:
        print("FAILED:", failed)
        sys.exit(1)


if __name__ == "__main__":
    main()
