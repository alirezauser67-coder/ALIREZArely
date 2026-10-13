import asyncio

import admin
import links
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

        try:
            cl = int(headers.get("content-length", "0") or 0)
        except ValueError:
            cl = 0
        body = extra
        if cl > len(body):
            if cl > 65536:
                writer.write(_resp("413 Payload Too Large", "413"))
                await writer.drain()
                return
            while len(body) < cl:
                chunk = await asyncio.wait_for(reader.read(cl - len(body)), 30)
                if not chunk:
                    break
                body += chunk

        path = target.split("?", 1)[0]
        if path.startswith("/admin"):
            writer.write(await admin.handle(method, target, headers, body, ctx))
        elif method != "GET":
            writer.write(_resp("405 Method Not Allowed", "405"))
        elif path in ("/", "/sub"):
            l1, l2 = links.build_links(ctx, headers.get("host", ""))
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
