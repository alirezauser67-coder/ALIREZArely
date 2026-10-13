import asyncio
import urllib.parse

import vless
import ws


def _resp(status, body, ctype="text/plain; charset=utf-8"):
    if isinstance(body, str):
        body = body.encode("utf-8")
    head = (
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n"
    ) % (status, ctype, len(body))
    return head.encode("ascii") + body


def build_links(ctx, host_hdr):
    uid = ctx["uuid"]
    tag = urllib.parse.quote(ctx["tag"])
    path_q = urllib.parse.quote(ctx["ws_path"])

    if ctx["domain"]:
        ws_host, ws_port = ctx["domain"], 443
    else:
        h = (host_hdr or "localhost").strip()
        ws_host, ws_port = h, 443
        if h.startswith("["):
            end = h.find("]")
            if end != -1:
                ws_host = h[:end + 1]
                rest = h[end + 1:]
                if rest.startswith(":") and rest[1:].isdigit():
                    ws_port = int(rest[1:])
        elif ":" in h:
            host_part, _, port_part = h.rpartition(":")
            if port_part.isdigit():
                ws_host, ws_port = host_part, int(port_part)

    if ws_port == 443:
        ws_q = "encryption=none&security=tls&sni=%s&type=ws&path=%s&host=%s" % (
            ws_host, path_q, ws_host)
        link_ws = "vless://%s@%s:443?%s#%s" % (uid, ws_host, ws_q, tag)
    else:
        ws_q = "encryption=none&security=none&type=ws&path=%s&host=%s:%d" % (
            path_q, ws_host, ws_port)
        link_ws = "vless://%s@%s:%d?%s#%s" % (uid, ws_host, ws_port, ws_q, tag)

    tcp_host = ctx["tcp_domain"] or ws_host
    tcp_port = ctx["tcp_public_port"]
    link_tcp = "vless://%s@%s:%d?encryption=none&type=tcp#%s" % (
        uid, tcp_host, tcp_port, tag)
    return link_ws, link_tcp


async def serve(reader, writer, prefix, ctx, peer="?"):
    log = ctx.get("log")
    try:
        head = bytearray(prefix)
        while b"\r\n\r\n" not in head:
            if len(head) > 32768:
                return
            chunk = await asyncio.wait_for(reader.read(4096), 30)
            if not chunk:
                return
            head += chunk
        raw = bytes(head)
        block, _, extra = raw.partition(b"\r\n\r\n")
        lines = block.split(b"\r\n")
        parts = lines[0].split(b" ")
        if len(parts) < 2:
            return
        method = parts[0].decode("ascii", "ignore")
        target = parts[1].decode("latin-1", "ignore")
        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")

        if headers.get("upgrade", "").lower() == "websocket" and headers.get("sec-websocket-key"):
            stream = await ws.accept(reader, writer, headers["sec-websocket-key"], extra)
            await vless.serve(stream, ctx, peer=peer, transport="ws")
            return

        path = target.split("?", 1)[0]
        if method != "GET":
            writer.write(_resp("405 Method Not Allowed", "405"))
        elif path in ("/", "/sub"):
            l1, l2 = build_links(ctx, headers.get("host", ""))
            writer.write(_resp("200 OK", l1 + "\n" + l2 + "\n"))
        elif path == "/healthz":
            writer.write(_resp("200 OK", "ok"))
        else:
            writer.write(_resp("404 Not Found", "404"))
        await writer.drain()
    except (asyncio.TimeoutError, ConnectionError):
        pass
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if log:
            log("http error %s: %s" % (peer, exc))
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
