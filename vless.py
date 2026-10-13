import asyncio
import ipaddress
import socket

BUF = 256 * 1024
HDR_LIMIT = 64 * 1024
CONNECT_TIMEOUT = 10
HEADER_TIMEOUT = 15


class TcpStream:
    def __init__(self, reader, writer, prefix=b""):
        self.reader = reader
        self.writer = writer
        self.prefix = prefix
        self.eof = False

    async def read(self, n):
        if self.prefix:
            if len(self.prefix) > n:
                out, self.prefix = self.prefix[:n], self.prefix[n:]
            else:
                out, self.prefix = self.prefix, b""
            return out
        if self.eof:
            return b""
        data = await self.reader.read(n)
        if not data:
            self.eof = True
        return data

    async def write(self, data):
        self.writer.write(data)
        await self.writer.drain()

    async def close(self):
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass


def parse_header(buf):
    if len(buf) < 18:
        return None
    ver = buf[0]
    user = bytes(buf[1:17])
    pos = 18 + buf[17]
    if len(buf) < pos + 4:
        return None
    cmd = buf[pos]
    port = int.from_bytes(buf[pos + 1:pos + 3], "big")
    at = buf[pos + 3]
    pos += 4
    if at == 1:
        if len(buf) < pos + 4:
            return None
        addr = ".".join(str(b) for b in buf[pos:pos + 4])
        pos += 4
    elif at == 2:
        if len(buf) < pos + 1:
            return None
        ln = buf[pos]
        pos += 1
        if len(buf) < pos + ln:
            return None
        addr = bytes(buf[pos:pos + ln]).decode("utf-8", "ignore")
        pos += ln
    elif at == 3:
        if len(buf) < pos + 16:
            return None
        addr = str(ipaddress.IPv6Address(bytes(buf[pos:pos + 16])))
        pos += 16
    else:
        raise ValueError("bad address type %d" % at)
    return ver, user, cmd, addr, port, pos


async def _read_header(stream):
    buf = bytearray()
    while True:
        chunk = await stream.read(4096)
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
        if len(buf) > HDR_LIMIT:
            raise ValueError("vless header too large")
        parsed = parse_header(buf)
        if parsed:
            return parsed, bytes(buf)


async def pump(src, dst):
    while True:
        data = await src.read(BUF)
        if not data:
            break
        await dst.write(data)


async def serve(stream, ctx, peer="?", transport="tcp"):
    log = ctx.get("log")
    try:
        parsed, raw = await asyncio.wait_for(_read_header(stream), HEADER_TIMEOUT)
        ver, user, cmd, addr, port, consumed = parsed
        if user != ctx["uuid_bytes"]:
            if log:
                log("reject %s from %s (bad uuid)" % (transport, peer))
            return
        leftover = raw[consumed:]
        if log:
            log("%s %s -> %s:%s" % (transport, peer, addr, port))
        if cmd == 1:
            await _tcp(stream, ctx, ver, addr, port, leftover)
        elif cmd == 2:
            await _udp(stream, ctx, ver, addr, port, leftover)
        elif log:
            log("unsupported vless command %s from %s" % (cmd, peer))
    except (asyncio.TimeoutError, ConnectionError):
        pass
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if log:
            log("%s error %s: %s" % (transport, peer, exc))
    finally:
        await stream.close()


async def _tcp(stream, ctx, ver, addr, port, leftover):
    log = ctx.get("log")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(addr, port), CONNECT_TIMEOUT
        )
    except Exception as exc:
        if log:
            log("connect fail %s:%s (%s)" % (addr, port, exc))
        return
    target = TcpStream(reader, writer)
    sock = writer.transport.get_extra_info("socket")
    if sock:
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
    t1 = t2 = None
    try:
        await stream.write(bytes([ver, 0]))
        if leftover:
            await target.write(leftover)
        t1 = asyncio.create_task(pump(stream, target))
        t2 = asyncio.create_task(pump(target, stream))
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        tasks = [t for t in (t1, t2) if t]
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await target.close()


class _UdpProto(asyncio.DatagramProtocol):
    def __init__(self):
        self.queue = asyncio.Queue()

    def datagram_received(self, data, addr):
        self.queue.put_nowait(data)


async def _udp(stream, ctx, ver, addr, port, leftover):
    log = ctx.get("log")
    loop = asyncio.get_running_loop()
    try:
        transport, proto = await loop.create_datagram_endpoint(
            _UdpProto, remote_addr=(addr, port)
        )
    except Exception as exc:
        if log:
            log("udp connect fail %s:%s (%s)" % (addr, port, exc))
        return
    t1 = t2 = None
    try:
        await stream.write(bytes([ver, 0]))

        async def from_client():
            pending = bytearray(leftover)
            while True:
                while len(pending) >= 2:
                    size = int.from_bytes(pending[:2], "big")
                    if len(pending) < 2 + size:
                        break
                    transport.sendto(bytes(pending[2:2 + size]))
                    del pending[:2 + size]
                chunk = await stream.read(BUF)
                if not chunk:
                    return
                pending += chunk

        async def to_client():
            while True:
                data = await proto.queue.get()
                await stream.write(len(data).to_bytes(2, "big") + data)

        t1 = asyncio.create_task(from_client())
        t2 = asyncio.create_task(to_client())
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        tasks = [t for t in (t1, t2) if t]
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        transport.close()
