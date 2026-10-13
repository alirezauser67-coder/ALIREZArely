import asyncio
import base64
import hashlib
import struct

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _unmask(payload, mask):
    n = len(payload)
    if n == 0:
        return payload
    m = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(m, "big")).to_bytes(n, "big")


class WSStream:
    def __init__(self, reader, writer, prefix=b""):
        self.reader = reader
        self.writer = writer
        self.prefix = prefix
        self.buf = bytearray()
        self.eof = False
        self.closed = False

    async def _read_exact(self, n):
        if self.prefix:
            if len(self.prefix) < n:
                more = await self.reader.readexactly(n - len(self.prefix))
                out = self.prefix + more
                self.prefix = b""
                return out
            out, self.prefix = self.prefix[:n], self.prefix[n:]
            return out
        return await self.reader.readexactly(n)

    async def _frame(self):
        head = await self._read_exact(2)
        op = head[0] & 0x0F
        ln = head[1] & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", await self._read_exact(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", await self._read_exact(8))[0]
        mask = await self._read_exact(4) if head[1] & 0x80 else None
        payload = await self._read_exact(ln) if ln else b""
        if mask:
            payload = _unmask(payload, mask)
        return op, payload

    async def _send(self, op, payload=b""):
        head = bytes([0x80 | op])
        ln = len(payload)
        if ln < 126:
            head += bytes([ln])
        elif ln < 65536:
            head += bytes([126]) + struct.pack(">H", ln)
        else:
            head += bytes([127]) + struct.pack(">Q", ln)
        self.writer.write(head + payload)
        await self.writer.drain()

    async def _fill(self):
        op, payload = await self._frame()
        if op == 0x8:
            self.eof = True
            if not self.closed:
                self.closed = True
                try:
                    await self._send(0x8, b"")
                except Exception:
                    pass
        elif op == 0x9:
            await self._send(0xA, payload)
        elif op != 0xA:
            self.buf += payload

    async def read(self, n):
        while not self.buf and not self.eof:
            try:
                await self._fill()
            except (asyncio.IncompleteReadError, ConnectionError, OSError):
                self.eof = True
        if not self.buf:
            return b""
        if len(self.buf) > n:
            out = bytes(self.buf[:n])
            del self.buf[:n]
            return out
        out = bytes(self.buf)
        self.buf.clear()
        return out

    async def write(self, data):
        await self._send(0x2, data)

    async def close(self):
        if not self.closed:
            self.closed = True
            try:
                await self._send(0x8, b"\x03\xe8")
            except Exception:
                pass
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass


async def accept(reader, writer, key, prefix=b""):
    token = base64.b64encode(hashlib.sha1((key + _GUID).encode()).digest()).decode()
    writer.write(
        (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n\r\n" % token
        ).encode("ascii")
    )
    await writer.drain()
    return WSStream(reader, writer, prefix)
