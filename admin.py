import asyncio
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


def _redirect(loc, cookie=None, clear=False):
    if clear:
        extra = "Set-Cookie: gwa=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0\r\n"
    elif cookie:
        extra = (
            "Set-Cookie: gwa=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400\r\n"
            % cookie
        )
    else:
        extra = ""
    return (
        "HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\n"
        "%sConnection: close\r\n\r\n" % (loc, extra)
    ).encode("ascii")


_CSS = (
    "body{font-family:system-ui,sans-serif;background:#111;color:#ddd;"
    "max-width:640px;margin:30px auto;padding:0 16px}"
    "input,button{font-size:15px;padding:8px;margin:4px 0;box-sizing:border-box}"
    "input{width:60%%}button{background:#2b6;color:#fff;border:0;cursor:pointer}"
    "pre{background:#222;padding:10px;white-space:pre-wrap;word-break:break-all}"
    "label{display:block;margin-top:10px;color:#9ab}"
    "code{color:#fc6}"
)


def _login_page(err=""):
    msg = '<p style="color:#f66">%s</p>' % _esc(err) if err else ""
    status = "401 Unauthorized" if err else "200 OK"
    return _resp(
        status,
        """<!doctype html><html><head><meta charset="utf-8"><title>admin</title>
<style>%s</style></head><body>
<h1>ALIREZArely admin</h1>%s
<form method="post" action="/admin/login">
<input type="password" name="password" placeholder="password" autofocus>
<button>Login</button></form></body></html>""" % (_CSS, msg),
    )


def _admin_page(ctx, host_hdr, note=""):
    st = ctx["state"]
    l1, l2 = links.build_links(ctx, host_hdr)
    tcp_host, tcp_port, tcp_src = links.tcp_target(ctx, "-")
    note_html = '<p style="color:#f66">%s</p>' % _esc(note) if note else ""
    return _resp(
        "200 OK",
        """<!doctype html><html><head><meta charset="utf-8"><title>admin</title>
<style>%s</style></head><body>
<h1>ALIREZArely admin</h1>%s
<p>uuid: <code>%s</code></p>
<label>links (same as /sub)</label><pre>%s
%s</pre>
<label>current tcp endpoint: %s:%s (%s)</label>
<form method="post" action="/admin/save">
<label>tcp host (empty = auto)</label><input name="host" id="host" value="%s">
<label>tcp port (empty = auto)</label><input name="port" id="port" value="%s">
<button>Save</button></form>
<button onclick="doTest()">Test tunnel</button>
<pre id="out"></pre>
<form method="post" action="/admin/logout"><button style="background:#833">Logout</button></form>
<script>
async function doTest(){
var o=document.getElementById("out");o.textContent="testing...";
var f=new URLSearchParams({host:document.getElementById("host").value,port:document.getElementById("port").value});
try{var r=await fetch("/admin/test",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:f});o.textContent=await r.text();}
catch(e){o.textContent="error: "+e;}
}
</script></body></html>"""
        % (
            _CSS,
            note_html,
            _esc(ctx["uuid"]),
            _esc(l1),
            _esc(l2),
            _esc(tcp_host),
            tcp_port,
            _esc(tcp_src),
            _esc(st.get("tcp_domain", "")),
            st.get("tcp_public_port", ""),
        ),
    )


async def _tunnel_test(ctx, host, port):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 6)
    except Exception as exc:
        return "connect FAIL %s:%s -> %s" % (host, port, exc)
    lines = ["connect OK %s:%s" % (host, port)]
    try:
        addr = b"ipinfo.io"
        hdr = (
            b"\x00"
            + ctx["uuid_bytes"]
            + b"\x00\x01"
            + (80).to_bytes(2, "big")
            + b"\x02"
            + bytes([len(addr)])
            + addr
        )
        req = hdr + (
            b"GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\n"
            b"Connection: close\r\nUser-Agent: curl\r\n\r\n"
        )
        writer.write(req)
        await writer.drain()
        buf = b""
        deadline = time.time() + 12
        while time.time() < deadline and len(buf) < 16384:
            try:
                chunk = await asyncio.wait_for(
                    reader.read(4096), max(0.5, deadline - time.time())
                )
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf += chunk
        if not buf:
            lines.append("tunnel FAIL: no response (uuid mismatch?)")
            return "\n".join(lines)
        if buf[:2] == b"\x00\x00":
            lines.append("vless header OK")
            buf = buf[2:]
        else:
            lines.append("tunnel FAIL: bad vless response %r" % buf[:4])
            return "\n".join(lines)
        if b"\r\n\r\n" in buf:
            status_line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            body = buf.split(b"\r\n\r\n", 1)[1].strip()
            lines.append("http %s" % status_line)
            text = body.decode("utf-8", "replace").strip()
            if text and all(c in "0123456789.:" for c in text) and len(text) >= 7:
                lines.append("egress IP: %s" % text)
            elif text:
                lines.append("body: %s" % text[:200])
        else:
            lines.append("raw: %r" % buf[:200])
    except Exception as exc:
        lines.append("tunnel FAIL: %s" % exc)
    finally:
        try:
            writer.close()
        except Exception:
            pass
    return "\n".join(lines)


async def handle(method, path, headers, body, ctx):
    if path == "/admin/login":
        if method != "POST":
            return _login_page()
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        if form.get("password", [""])[0] == ctx["admin_password"]:
            return _redirect("/admin", cookie=_token(ctx))
        return _login_page("wrong password")

    if not _authed(ctx, headers):
        if method == "GET" and path == "/admin":
            return _login_page()
        return _login_page("login required")

    if path == "/admin" and method == "GET":
        return _admin_page(ctx, headers.get("host", ""))

    if path == "/admin/logout" and method == "POST":
        return _redirect("/admin", clear=True)

    if path == "/admin/save" and method == "POST":
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        host = form.get("host", [""])[0].strip()
        port_s = form.get("port", [""])[0].strip()
        err = ""
        if host and not _HOST_RE.match(host):
            err = "bad host"
        port_v = None
        if port_s:
            if port_s.isdigit() and 1 <= int(port_s) <= 65535:
                port_v = int(port_s)
            else:
                err = err or "bad port"
        if err:
            return _admin_page(ctx, headers.get("host", ""), err)
        if host:
            ctx["state"]["tcp_domain"] = host
        else:
            ctx["state"].pop("tcp_domain", None)
        if port_v is not None:
            ctx["state"]["tcp_public_port"] = port_v
        else:
            ctx["state"].pop("tcp_public_port", None)
        save_err = save_state(ctx["state"])
        if save_err:
            return _admin_page(
                ctx,
                headers.get("host", ""),
                "saved in memory only (state.json: %s)" % save_err,
            )
        return _redirect("/admin")

    if path == "/admin/test" and method == "POST":
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        host = form.get("host", [""])[0].strip()
        port_s = form.get("port", [""])[0].strip()
        if not host:
            t_host, t_port, _ = links.tcp_target(ctx, "127.0.0.1")
            host, port_s = t_host, str(t_port)
        if not (
            host
            and _HOST_RE.match(host)
            and port_s.isdigit()
            and 1 <= int(port_s) <= 65535
        ):
            return _resp("200 OK", "bad host/port", ctype="text/plain; charset=utf-8")
        text = await _tunnel_test(ctx, host, int(port_s))
        return _resp("200 OK", text, ctype="text/plain; charset=utf-8")

    return _resp("404 Not Found", "404")
