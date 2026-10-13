import asyncio
import os
import time
import uuid as uuidlib

import admin
import httpd
import links
import vless


def log(msg):
    print("[%s] %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg), flush=True)


def build_ctx():
    state = admin.load_state()
    env_uuid = os.getenv("UUID", "").strip()
    chosen = env_uuid or state.get("uuid") or str(uuidlib.uuid4())
    try:
        uid = uuidlib.UUID(chosen.strip())
    except ValueError:
        log("error: invalid UUID")
        raise SystemExit(1)
    if state.get("uuid") != str(uid):
        state["uuid"] = str(uid)
        err = admin.save_state(state)
        if err:
            log("warn: state not persisted (%s)" % err)
    return {
        "uuid": str(uid),
        "uuid_bytes": uid.bytes,
        "tag": os.getenv("TAG", "ALIREZArely").strip() or "ALIREZArely",
        "domain": os.getenv("DOMAIN", "").strip(),
        "ws_path": os.getenv("WS_PATH", "/ws").strip() or "/ws",
        "admin_password": os.getenv("ADMIN_PASSWORD", "admin").strip() or "admin",
        "state": state,
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
    candidates = [int(os.getenv("PORT", "8080"))]
    if any(k.startswith("RAILWAY_") for k in os.environ):
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
    host, port, src = links.endpoint(ctx, ctx["domain"] or "-")
    log("public: %s:%s (%s)" % (host, port, src))
    log("link  : %s" % links.build_link(ctx, ctx["domain"]))
    await asyncio.gather(*[s.serve_forever() for s in servers])


if __name__ == "__main__":
    CTX = build_ctx()
    try:
        asyncio.run(run(CTX))
    except KeyboardInterrupt:
        pass
