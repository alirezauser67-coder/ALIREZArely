import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.parse
import uuid as uuidlib

ROOT = os.path.dirname(os.path.abspath(__file__))
XRAY_HOST = "127.0.0.1"
XRAY_PORT = 18443


def log(msg):
    print("[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg), flush=True)


def state_path():
    data_dir = (
        os.getenv("DATA_DIR", "").strip()
        or ("/data" if os.name != "nt" and os.path.isdir("/data") else "data")
    )
    return os.path.join(data_dir, "state.json")


def load_uuid():
    env_uuid = os.getenv("UUID", "").strip()
    saved = None
    try:
        with open(state_path(), "r", encoding="utf-8") as fh:
            saved = (json.load(fh) or {}).get("uuid")
    except Exception:
        pass
    chosen = env_uuid or saved or str(uuidlib.uuid4())
    if not env_uuid:
        try:
            path = state_path()
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"uuid": chosen}, fh)
        except Exception as exc:
            log("warn: state not persisted (%s)" % exc)
    try:
        return str(uuidlib.UUID(chosen.strip()))
    except ValueError:
        log("error: invalid UUID")
        raise SystemExit(1)


def render_config(uid, path, mode):
    cfg = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": XRAY_HOST,
                "port": XRAY_PORT,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": uid}],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "xhttp",
                    "xhttpSettings": {"path": path, "mode": mode},
                },
            }
        ],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }
    cfg_path = os.path.join(ROOT, "config.json")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    return cfg_path


def start_xray(cfg_path):
    xray = (
        os.getenv("XRAY_BIN", "").strip()
        or shutil.which("xray")
        or os.path.join(ROOT, "xray")
    )
    return subprocess.Popen([xray, "run", "-c", cfg_path])


def build_link(uid, host, port, path, mode, tag):
    q_path = urllib.parse.quote(path, safe="")
    if port == 443:
        q = "security=tls&sni=%s&type=xhttp&mode=%s&path=%s&host=%s" % (
            host, mode, q_path, host)
        return "vless://%s@%s:443?%s#%s" % (uid, host, q, urllib.parse.quote(tag))
    q = "security=none&type=xhttp&mode=%s&path=%s&host=%s:%d" % (
        mode, q_path, host, port)
    return "vless://%s@%s:%d?%s#%s" % (
        uid, host, port, q, urllib.parse.quote(tag))


def split_host(hdr):
    h = (hdr or "localhost").strip()
    host, port = h, 443
    if h.startswith("["):
        end = h.find("]")
        if end != -1:
            host = h[:end + 1]
            rest = h[end + 1:]
            if rest.startswith(":") and rest[1:].isdigit():
                port = int(rest[1:])
    elif ":" in h:
        name, _, p = h.rpartition(":")
        if p.isdigit() and name:
            host, port = name, int(p)
    return host, port


async def pipe(a, b):
    try:
        while True:
            d = await a.read(65536)
            if not d:
                break
            b.write(d)
            await b.drain()
    except Exception:
        pass
    finally:
        try:
            b.close()
        except Exception:
            pass


async def handle(reader, writer, ctx):
    log_line = ctx.get("log")
    try:
        head = bytearray()
        while b"\r\n\r\n" not in head:
            if len(head) > 32768:
                return
            chunk = await asyncio.wait_for(reader.read(4096), 30)
            if not chunk:
                return
            head += chunk
        block = bytes(head).split(b"\r\n", 1)[0]
        parts = block.split(b" ")
        if len(parts) < 2:
            return
        method = parts[0].decode("ascii", "ignore")
        target = parts[1].decode("latin-1", "ignore")
        path = target.split("?", 1)[0]
        headers = {}
        for line in bytes(head).split(b"\r\n")[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")

        if method == "GET" and path in ("/", "/sub", "/healthz"):
            if path == "/healthz":
                body = "ok\n"
            else:
                host, port = split_host(headers.get("host", ""))
                host = ctx["domain"] or host
                port = 443 if ctx["domain"] else port
                body = build_link(
                    ctx["uuid"], host, port, ctx["xh_path"], ctx["xh_mode"], ctx["tag"]
                ) + "\n"
            data = body.encode("utf-8")
            writer.write(
                (
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
                    "Content-Length: %d\r\nConnection: close\r\n\r\n" % len(data)
                ).encode("ascii")
                + data
            )
            await writer.drain()
            return

        try:
            xr, xw = await asyncio.wait_for(
                asyncio.open_connection(XRAY_HOST, XRAY_PORT), 5
            )
        except Exception as exc:
            if log_line:
                log_line("xray connect fail: %s" % exc)
            return
        xw.write(bytes(head))
        await xw.drain()
        await asyncio.gather(pipe(reader, xw), pipe(xr, writer))
    except (asyncio.TimeoutError, ConnectionError):
        pass
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if log_line:
            log_line("conn error: %s" % exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def run(ctx):
    candidates = [int(os.getenv("PORT", "8080"))]
    if any(k.startswith("RAILWAY_") for k in os.environ):
        for extra in (8080, 443):
            if extra not in candidates:
                candidates.append(extra)
    servers = []
    for p in sorted(candidates):
        try:
            servers.append(
                await asyncio.start_server(
                    lambda r, w: handle(r, w, ctx), "0.0.0.0", p
                )
            )
        except OSError as exc:
            log("skip port %d (%s)" % (p, exc))
    if not servers:
        log("error: could not bind any port")
        raise SystemExit(1)
    log("uuid  : %s" % ctx["uuid"])
    log("listen: %s" % ", ".join(str(s.sockets[0].getsockname()[1]) for s in servers))
    log("xhttp : path=%s mode=%s -> %s:%d" % (
        ctx["xh_path"], ctx["xh_mode"], XRAY_HOST, XRAY_PORT))
    host, port = split_host("-")
    host = ctx["domain"] or host
    port = 443 if ctx["domain"] else 8080
    log("link  : %s" % build_link(
        ctx["uuid"], host, port, ctx["xh_path"], ctx["xh_mode"], ctx["tag"]))
    await asyncio.gather(*[s.serve_forever() for s in servers])


def main():
    uid = load_uuid()
    ctx = {
        "uuid": uid,
        "tag": os.getenv("TAG", "ALIREZArely").strip() or "ALIREZArely",
        "domain": os.getenv("DOMAIN", "").strip(),
        "xh_path": os.getenv("XHTTP_PATH", "/xh").strip() or "/xh",
        "xh_mode": os.getenv("XHTTP_MODE", "auto").strip() or "auto",
        "log": log,
    }
    cfg_path = render_config(uid, ctx["xh_path"], ctx["xh_mode"])
    proc = start_xray(cfg_path)
    log("xray  : pid %d" % proc.pid)

    def on_term(signum, frame):
        try:
            proc.terminate()
        except Exception:
            pass
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    async def watch():
        while True:
            await asyncio.sleep(2)
            if proc.poll() is not None:
                log("error: xray exited with code %s" % proc.returncode)
                os._exit(1)

    async def boot():
        asyncio.ensure_future(watch())
        await run(ctx)

    try:
        asyncio.run(boot())
    except KeyboardInterrupt:
        pass
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    main()
