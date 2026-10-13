import asyncio
import base64
import hashlib
import json
import os
import re
import time
import urllib.parse

import links

_HOST_RE = re.compile(r"^[A-Za-z0-9.\-:\[\]]{1,253}$")


def state_path():
    data_dir = (
        os.getenv("DATA_DIR", "").strip()
        or ("/data" if os.name != "nt" and os.path.isdir("/data") else "data")
    )
    return os.path.join(data_dir, "state.json")


def load_state():
    try:
        with open(state_path(), "r", encoding="utf-8") as fh:
            return json.load(fh) or {}
    except Exception:
        return {}


def save_state(data):
    try:
        path = state_path()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        return None
    except Exception as exc:
        return str(exc)


def _token(ctx):
    return hashlib.sha256(
        (ctx["admin_password"] + "|" + ctx["uuid"]).encode("utf-8")
    ).hexdigest()


def _authed(ctx, headers):
    for part in headers.get("cookie", "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == "gwa" and v == _token(ctx):
            return True
    return False


def _esc(s):
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _resp(status, body, ctype="text/html; charset=utf-8"):
    if isinstance(body, str):
        body = body.encode("utf-8")
    head = (
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n"
    ) % (status, ctype, len(body))
    return head.encode("ascii") + body


def _redirect(loc):
    return (
        "HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\n"
        "Connection: close\r\n\r\n" % loc
    ).encode("ascii")


def _login_redirect(ctx):
    return (
        "HTTP/1.1 302 Found\r\nLocation: /admin\r\nContent-Length: 0\r\n"
        "Set-Cookie: gwa=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400\r\n"
        "Connection: close\r\n\r\n" % _token(ctx)
    ).encode("ascii")


def _logout_redirect():
    return (
        "HTTP/1.1 302 Found\r\nLocation: /admin\r\nContent-Length: 0\r\n"
        "Set-Cookie: gwa=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,sans-serif;background:#0f1419;color:#e7ecf3;max-width:720px;margin:0 auto;padding:24px 16px}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.top h1{font-size:22px;font-weight:700}
.top h1 span{color:#3ea6ff}
.card{background:#1a2332;border:1px solid #2a3a52;border-radius:12px;padding:18px;margin-bottom:16px}
.card h2{font-size:13px;color:#8bb9ff;margin-bottom:14px;text-transform:uppercase;letter-spacing:1px}
.row{display:flex;gap:8px;align-items:center;margin:8px 0;flex-wrap:wrap}
.row .k{color:#8a9bb3;min-width:100px;font-size:13px}
.mono{font-family:Consolas,Menlo,monospace;font-size:12px;background:#0d1117;border:1px solid #2a3a52;border-radius:8px;padding:10px;width:100%;color:#9ece6a;word-break:break-all}
input{background:#0d1117;border:1px solid #2a3a52;border-radius:8px;color:#e7ecf3;padding:10px;font-size:14px;width:100%;font-family:Consolas,Menlo,monospace}
button{background:#3ea6ff;color:#081018;border:0;border-radius:8px;padding:9px 16px;font-size:13px;font-weight:600;cursor:pointer}
button.sec{background:#2a3a52;color:#cfe3ff}
button.danger{background:#e5534b;color:#fff}
.btns{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap;align-items:center}
.badge{display:inline-block;background:#2a3a52;color:#ffd166;border-radius:6px;padding:3px 9px;font-size:12px}
.banner{border-radius:8px;padding:10px 12px;margin-bottom:14px;font-size:14px}
.okb{background:#143d2a;color:#7ee2a8;border:1px solid #1f6b45}
.errb{background:#3d1a1a;color:#ffb4b4;border:1px solid #6b2a2a}
.warnb{background:#3d321a;color:#ffd166;border:1px solid #6b5a2a;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
pre.out{background:#0d1117;border:1px solid #2a3a52;border-radius:8px;padding:10px;font-size:12px;white-space:pre-wrap;margin-top:10px;color:#c0caf5;font-family:Consolas,Menlo,monospace}
.hint{color:#8a9bb3;font-size:12px;margin-top:8px;line-height:1.5}
.val{font-family:Consolas,Menlo,monospace;font-size:13px;color:#e7ecf3;word-break:break-all}
"""


def _login_page(err=""):
    msg = '<div class="banner errb">%s</div>' % _esc(err) if err else ""
    status = "401 Unauthorized" if err else "200 OK"
    return _resp(
        status,
        """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>admin - ALIREZArely</title>
<style>%s</style></head><body>
<div class="card" style="max-width:380px;margin:60px auto">
<h2>ALIREZArely - Login</h2>%s
<form method="post" action="/admin/login">
<input type="password" name="password" placeholder="password" autofocus>
<div class="btns"><button>Login</button></div>
</form>
</div></body></html>""" % (_CSS, msg),
    )


def _page(ctx, host_hdr, note="", saved=False):
    st = ctx["state"]
    link = links.build_link(ctx, host_hdr)
    pub_host, pub_port, pub_src = links.endpoint(ctx, host_hdr)
    auto_host, auto_port, _ = links.endpoint(ctx, "")
    override = bool(st.get("host") or st.get("port"))
    banners = ""
    if note:
        banners += '<div class="banner errb">%s</div>' % _esc(note)
    if saved:
        banners += '<div class="banner okb">Settings saved.</div>'
    override_html = ""
    if override:
        override_html = """<div class="banner warnb">Manual override is active.
<form method="post" action="/admin/reset"><button class="danger">Reset to auto</button></form></div>"""
    return _resp(
        "200 OK",
        """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>admin - ALIREZArely</title>
<style>%s</style></head><body>
<div class="top"><h1>&#9889; <span>ALIREZArely</span></h1>
<form method="post" action="/admin/logout"><button class="sec">Logout</button></form></div>
%s

<div class="card"><h2>Server</h2>
<div class="row"><span class="k">UUID</span>
<input readonly id="uuid" value="%s" onclick="this.select()"></div>
<div class="btns"><button class="sec" onclick="copy('uuid')">Copy UUID</button></div>
<div class="row" style="margin-top:14px"><span class="k">Public</span>
<span class="val">%s:%s</span> <span class="badge">%s</span></div>
</div>

<div class="card"><h2>Client link</h2>
<div class="row"><input readonly class="mono" id="l1" value="%s" onclick="this.select()"></div>
<div class="btns"><button class="sec" onclick="copy('l1')">Copy link</button>
<span class="hint" style="margin:0">same as /sub</span></div>
</div>

<div class="card"><h2>Settings</h2>
%s
<div class="hint">Host = your domain (or leave empty for auto). Port = 443.
Paste <code>domain:port</code> or a full <code>vless://</code> link into Host if you want - it is parsed automatically.</div>
<form method="post" action="/admin/save" style="margin-top:12px">
<div class="row"><span class="k">Public host</span>
<input name="host" id="host" placeholder="auto: %s" value="%s"></div>
<div class="row"><span class="k">Public port</span>
<input name="port" id="port" placeholder="auto: %s" value="%s"></div>
<div class="btns"><button>Save</button></div>
</form>
</div>

<div class="card"><h2>Test</h2>
<div class="hint">Connects to your public endpoint over WebSocket, runs a VLESS tunnel to ipinfo.io
and shows the egress IP. Tests the exact same path clients use.</div>
<div class="btns"><button onclick="doTest()">Run test</button></div>
<pre class="out" id="out"></pre>
</div>

<script>
function copy(i){var e=document.getElementById(i);e.select();try{document.execCommand("copy");}catch(x){}
if(navigator.clipboard){navigator.clipboard.writeText(e.value);}}
async function doTest(){
var o=document.getElementById("out");o.textContent="testing...";
var f=new URLSearchParams({host:document.getElementById("host").value,port:document.getElementById("port").value});
try{var r=await fetch("/admin/test",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:f});o.textContent=await r.text();}
catch(e){o.textContent="error: "+e;}}
</script></body></html>"""
        % (
            _CSS,
            banners,
            _esc(ctx["uuid"]),
            _esc(pub_host),
            pub_port,
            _esc(pub_src),
            _esc(link),
            override_html,
            _esc(auto_host),
            _esc(st.get("host", "")),
            _esc(auto_port),
            st.get("port", ""),
        ),
    )


def _norm_host_port(host, port_s):
    h = host.strip()
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]
    h = h.split("?", 1)[0].split("#", 1)[0]
    if "@" in h:
        h = h.rsplit("@", 1)[1]
    h = h.strip()
    embedded = None
    if h.startswith("["):
        end = h.find("]")
        if end != -1:
            rest = h[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                embedded = int(rest[1:])
            h = h[:end + 1]
    elif h.count(":") == 1:
        name, _, p = h.partition(":")
        if p.isdigit():
            embedded = int(p)
            h = name
    port_v = None
    if port_s:
        if port_s.isdigit() and 1 <= int(port_s) <= 65535:
            port_v = int(port_s)
        else:
            return None, None, "bad port"
    if embedded is not None:
        if not 1 <= embedded <= 65535:
            return None, None, "bad port in host"
        port_v = embedded
    if not h:
        return "", port_v, ""
    if not _HOST_RE.match(h):
        return None, None, "bad host"
    return h, port_v, ""


def _ws_frame(payload):
    mask = os.urandom(4)
    ln = len(payload)
    h = bytes([0x82])
    if ln < 126:
        h += bytes([0x80 | ln])
    elif ln < 65536:
        h += bytes([0x80 | 126]) + ln.to_bytes(2, "big")
    else:
        h += bytes([0x80 | 127]) + ln.to_bytes(8, "big")
    return h + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


async def _ws_tunnel_test(ctx, host, port):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 6)
    except Exception as exc:
        return "connect FAIL %s:%s -> %s" % (host, port, exc)
    lines = ["connect OK %s:%s" % (host, port)]
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
            "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n" % (ctx["ws_path"], host, port, key)
        ).encode()
        writer.write(req)
        await writer.drain()
        buf = b""
        deadline = time.time() + 8
        while b"\r\n\r\n" not in buf and time.time() < deadline:
            try:
                chunk = await asyncio.wait_for(
                    reader.read(4096), max(0.5, deadline - time.time())
                )
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        if b" 101" not in head.split(b"\r\n")[0]:
            lines.append("websocket FAIL: %r" % head[:120])
            return "\n".join(lines)
        lines.append("websocket OK")

        addr = b"ipinfo.io"
        vhdr = (
            b"\x00"
            + ctx["uuid_bytes"]
            + b"\x00\x01"
            + (80).to_bytes(2, "big")
            + b"\x02"
            + bytes([len(addr)])
            + addr
        )
        payload = vhdr + (
            b"GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\n"
            b"Connection: close\r\nUser-Agent: curl\r\n\r\n"
        )
        writer.write(_ws_frame(payload))
        await writer.drain()

        data = bytearray(rest)
        out = bytearray()
        deadline = time.time() + 12
        while time.time() < deadline and len(out) < 16384:
            progressed = True
            while progressed and len(data) >= 2:
                progressed = False
                ln = data[1] & 0x7F
                pos = 2
                if ln == 126:
                    if len(data) < 4:
                        break
                    ln = int.from_bytes(data[2:4], "big")
                    pos = 4
                elif ln == 127:
                    if len(data) < 10:
                        break
                    ln = int.from_bytes(data[2:10], "big")
                    pos = 10
                if data[1] & 0x80:
                    if len(data) < pos + 4:
                        break
                    pos += 4
                if len(data) < pos + ln:
                    break
                out += data[pos:pos + ln]
                del data[:pos + ln]
                progressed = True
            if b"\r\n\r\n" in out and len(out) > out.index(b"\r\n\r\n") + 4 + 0 and not progressed:
                if len(out) > out.index(b"\r\n\r\n") + 4:
                    break
            try:
                chunk = await asyncio.wait_for(
                    reader.read(4096), max(0.5, deadline - time.time())
                )
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            data += chunk
        if not out:
            lines.append("tunnel FAIL: no data")
            return "\n".join(lines)
        if out[:2] == b"\x00\x00":
            lines.append("vless header OK")
            out = out[2:]
        else:
            lines.append("tunnel FAIL: bad vless response %r" % bytes(out[:4]))
            return "\n".join(lines)
        if b"\r\n\r\n" in out:
            status_line = out.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            body = bytes(out.split(b"\r\n\r\n", 1)[1]).strip()
            lines.append("http %s" % status_line)
            text = body.decode("utf-8", "replace").strip()
            if text and all(c in "0123456789.:" for c in text) and len(text) >= 7:
                lines.append("egress IP: %s" % text)
            elif text:
                lines.append("body: %s" % text[:200])
        else:
            lines.append("raw: %r" % bytes(out[:200]))
    except Exception as exc:
        lines.append("tunnel FAIL: %s" % exc)
    finally:
        try:
            writer.close()
        except Exception:
            pass
    return "\n".join(lines)


async def handle(method, target, headers, body, ctx):
    path, _, query = target.partition("?")
    qs = urllib.parse.parse_qs(query)

    if path == "/admin/login":
        if method != "POST":
            return _login_page()
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        if form.get("password", [""])[0] == ctx["admin_password"]:
            return _login_redirect(ctx)
        return _login_page("wrong password")

    if not _authed(ctx, headers):
        if method == "GET" and path == "/admin":
            return _login_page()
        return _login_page("login required")

    if path == "/admin" and method == "GET":
        saved = qs.get("saved", [""])[0] == "1"
        return _page(ctx, headers.get("host", ""), saved=saved)

    if path == "/admin/logout" and method == "POST":
        return _logout_redirect()

    if path == "/admin/reset" and method == "POST":
        ctx["state"].pop("host", None)
        ctx["state"].pop("port", None)
        save_state(ctx["state"])
        return _redirect("/admin?saved=1")

    if path == "/admin/save" and method == "POST":
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        host_raw = form.get("host", [""])[0]
        port_raw = form.get("port", [""])[0].strip()
        host, port_v, err = _norm_host_port(host_raw, port_raw)
        if err:
            return _page(ctx, headers.get("host", ""), note=err)
        if host:
            ctx["state"]["host"] = host
        else:
            ctx["state"].pop("host", None)
        if port_v is not None:
            ctx["state"]["port"] = port_v
        else:
            ctx["state"].pop("port", None)
        save_err = save_state(ctx["state"])
        if save_err:
            return _page(
                ctx,
                headers.get("host", ""),
                note="saved in memory only (state.json: %s)" % save_err,
            )
        return _redirect("/admin?saved=1")

    if path == "/admin/test" and method == "POST":
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        host_raw = form.get("host", [""])[0]
        port_raw = form.get("port", [""])[0].strip()
        pub_host, pub_port, _ = links.endpoint(ctx, headers.get("host", ""))
        if not host_raw.strip() and not port_raw:
            host_raw, port_raw = pub_host, str(pub_port)
        host, port_v, err = _norm_host_port(host_raw, port_raw)
        if err or not host or not port_v:
            return _resp(
                "200 OK",
                "bad host/port (%s)" % (err or "missing"),
                ctype="text/plain; charset=utf-8",
            )
        text = await _ws_tunnel_test(ctx, host, port_v)
        return _resp("200 OK", text, ctype="text/plain; charset=utf-8")

    return _resp("404 Not Found", "404")
