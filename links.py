import urllib.parse


def _int_or_none(v):
    try:
        n = int(v)
        return n if 1 <= n <= 65535 else None
    except (TypeError, ValueError):
        return None


def tcp_target(ctx, fallback_host):
    st = ctx.get("state") or {}
    if st.get("tcp_domain"):
        host, src = str(st["tcp_domain"]), "admin"
    elif ctx.get("railway_tcp_domain"):
        host, src = ctx["railway_tcp_domain"], "railway"
    elif ctx.get("tcp_domain"):
        host, src = ctx["tcp_domain"], "env"
    else:
        host, src = fallback_host, "default"
    port = (
        _int_or_none(st.get("tcp_public_port"))
        or ctx.get("railway_tcp_port")
        or ctx.get("tcp_public_port")
        or 9443
    )
    return host, port, src


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

    tcp_host, tcp_port, _ = tcp_target(ctx, ws_host)
    link_tcp = "vless://%s@%s:%d?encryption=none&type=tcp#%s" % (
        uid, tcp_host, tcp_port, tag)
    return link_ws, link_tcp
