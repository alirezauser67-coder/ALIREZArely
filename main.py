import asyncio
import json
import os
import time
import uuid as uuidlib

import httpd
import vless


def log(msg):
    print("[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg), flush=True)


def _state_path():
    data_dir = (
        os.getenv("DATA_DIR", "").strip()
        or ("/data" if os.name != "nt" and os.path.isdir("/data") else "data")
    )
    return os.path.join(data_dir, "state.json")


def load_uuid():
    env_uuid = os.getenv("UUID", "").strip()
    saved = None
    try:
        with open(_state_path(), "r", encoding="utf-8") as fh:
            saved = (json.load(fh) or {}).get("uuid")
    except Exception:
        pass
    chosen = env_uuid or saved or str(uuidlib.uuid4())
    if not env_uuid:
        try:
            path = _state_path()
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"uuid": chosen}, fh)
        except Exception as exc:
            log("warn: state not persisted (%s)" % exc)
    return chosen


def _env_int(name):
    raw = os.getenv(name, "").strip()
    return int(raw) if raw.isdigit() else None


def build_ctx():
    try:
        uid = uuidlib.UUID(load_uuid().strip())
    except ValueError:
        log("error: invalid UUID")
        raise SystemExit(1)
    return {
        "uuid": str(uid),
        "uuid_bytes": uid.bytes,
        "tag": os.getenv("TAG", "ALIREZArely").strip() or "ALIREZArely",
        "domain": os.getenv("DOMAIN", "").strip(),
        "tcp_domain": os.getenv("TCP_DOMAIN", "").strip(),
        "tcp_public_port": _env_int("TCP_PUBLIC_PORT"),
        "railway_tcp_domain": os.getenv("RAILWAY_TCP_PROXY_DOMAIN", "").strip(),
        "railway_tcp_port": _env_int("RAILWAY_TCP_PROXY_PORT"),
        "ws_path": os.getenv("WS_PATH", "/ws").strip() or "/ws",
        "log": log,
    }


async def handle(reader, writer, ctx):
    peer = writer.get_extra_info("peername")
    peer = "%s:%s" % (peer[0], peer[1]) if peer else "?"
    try:
        first = await asyncio.wait_for(reader.read(1), 20)
        if not first:
            writer.close()
            return
        b0 = first[0]
        if b0 == 0:
            await vless.serve(
                vless.TcpStream(reader, writer, first), ctx, peer=peer, transport="tcp"
            )
        elif 65 <= b0 <= 90:
            await httpd.serve(reader, writer, first, ctx, peer=peer)
        else:
            writer.close()
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        log("conn error %s: %s" % (peer, exc))
        try:
            writer.close()
        except Exception:
            pass


async def run(ctx):
    candidates = [
        int(os.getenv("PORT", "8080")),
        int(os.getenv("TCP_PORT", "9443")),
    ]
    if os.getenv("RAILWAY_ENVIRONMENT"):
        for extra in (8080, 443):
            if extra not in candidates:
                candidates.append(extra)
    servers = []
    for p in sorted(candidates):
        try:
            servers.append(
                await asyncio.start_server(lambda r, w: handle(r, w, ctx), "0.0.0.0", p)
            )
        except OSError as exc:
            log("skip port %d (%s)" % (p, exc))
    if not servers:
        log("error: could not bind any port")
        raise SystemExit(1)
    log("uuid  : %s" % ctx["uuid"])
    log("listen: %s" % ", ".join(str(s.sockets[0].getsockname()[1]) for s in servers))
    tcp_host, tcp_port, tcp_src = httpd.tcp_target(ctx, ctx["domain"] or "-")
    log("tcp   : %s:%s (%s)" % (tcp_host, tcp_port, tcp_src))
    if ctx["domain"]:
        l1, l2 = httpd.build_links(ctx, ctx["domain"])
        log("link1 : %s" % l1)
        log("link2 : %s" % l2)
    else:
        log("sub   : GET /sub (plain text, no auth)")
    await asyncio.gather(*[s.serve_forever() for s in servers])


if __name__ == "__main__":
    CTX = build_ctx()
    try:
        asyncio.run(run(CTX))
    except KeyboardInterrupt:
        pass
