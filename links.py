import urllib.parse


def _int_or_none(v):
    try:
        n = int(v)
        return n if 1 <= n <= 65535 else None
    except (TypeError, ValueError):
        return None


def _split_host(hdr):
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


def endpoint(ctx, host_hdr):
    st = ctx.get("state") or {}
    port_override = _int_or_none(st.get("port"))
    if st.get("host"):
        return str(st["host"]), port_override or 443, "admin"
    if ctx.get("domain"):
        return ctx["domain"], port_override or 443, "env"
    host, port = _split_host(host_hdr)
    return host, port_override or port, "host-header"


def build_link(ctx, host_hdr):
    host, port, _ = endpoint(ctx, host_hdr)
    uid = ctx["uuid"]
    tag = urllib.parse.quote(ctx["tag"])
    path_q = urllib.parse.quote(ctx["ws_path"])
    if port == 443:
        q = "encryption=none&security=tls&sni=%s&type=ws&path=%s&host=%s" % (
            host, path_q, host)
        return "vless://%s@%s:443?%s#%s" % (uid, host, q, tag)
    q = "encryption=none&security=none&type=ws&path=%s&host=%s:%d" % (
        path_q, host, port)
    return "vless://%s@%s:%d?%s#%s" % (uid, host, port, q, tag)
