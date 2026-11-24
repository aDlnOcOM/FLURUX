"""RFC 9298 UDP proxy over TLS, HTTP/1.1 Upgrade and RFC 9297 DATAGRAM capsules."""

import asyncio
import base64
import hmac
import json
import ssl
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

MAX_PACKET = 65507
MAX_SESSIONS = 64
IDLE = 120


def varint(value: int) -> bytes:
    """Encode a QUIC variable-length integer."""
    for index, size in enumerate((1, 2, 4, 8)):
        if 0 <= value < 1 << (8 * size - 2):
            return (value | (index << (8 * size - 2))).to_bytes(size, "big")
    raise ValueError("Invalid capsule integer")


async def read_int(reader: asyncio.StreamReader) -> int:
    """Read one QUIC variable-length integer."""
    first = (await reader.readexactly(1))[0]
    size = 1 << (first >> 6)
    return int.from_bytes(bytes([first & 63]) + await reader.readexactly(size - 1), "big")


async def headers(reader: asyncio.StreamReader) -> tuple[str, dict[str, str]]:
    """Read a bounded HTTP/1.1 header section."""
    raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 12)
    lines = raw.decode("latin-1").strip().split("\r\n")
    pairs = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep or name.lower() in pairs:
            raise ValueError("Invalid HTTP headers")
        pairs[name.lower()] = value.strip()
    return lines[0], pairs


def upgrade(fields: dict[str, str]) -> bool:
    """Check both mandatory HTTP Upgrade fields."""
    return (
        "upgrade" in [s.strip().lower() for s in fields.get("connection", "").split(",")]
        and fields.get("upgrade", "").lower() == "connect-udp"
    )


def endpoint(c: dict[str, Any]) -> str:
    """Return the expanded RFC 9298 default URI template."""
    return (
        "/.well-known/masque/udp/"
        + quote(str(c["target"]), safe="")
        + "/"
        + str(c["target_port"])
        + "/"
    )


def credential(c: dict[str, Any]) -> str:
    """Encode the per-profile basic proxy credential."""
    return "Basic " + base64.b64encode((c["user"] + ":" + c["password"]).encode()).decode("ascii")


async def exchange(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    queue: asyncio.Queue[bytes],
    send: Callable[[bytes], None],
) -> None:
    """Move datagrams in both directions until either side closes or becomes idle."""
    loop = asyncio.get_running_loop()
    last = loop.time()

    async def upload() -> None:
        nonlocal last
        while True:
            data = await queue.get()
            last = loop.time()
            writer.write(b"\0" + varint(len(data) + 1) + b"\0" + data)
            await writer.drain()

    async def download() -> None:
        nonlocal last
        while True:
            kind = await read_int(reader)
            size = await read_int(reader)
            if size > 1_048_576:
                raise ValueError("Oversize capsule")
            payload = await reader.readexactly(size)
            if kind == 0 and payload:
                n = 1 << (payload[0] >> 6)
                if (
                    len(payload) >= n
                    and not (payload[0] & 63)
                    and not any(payload[1:n])
                    and len(payload) - n <= MAX_PACKET
                ):
                    send(payload[n:])
                    last = loop.time()

    async def idle() -> None:
        while loop.time() - last < IDLE:
            await asyncio.sleep(5)

    tasks = [asyncio.create_task(coro()) for coro in (upload, download, idle)]
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class Udp(asyncio.DatagramProtocol):
    """Deliver UDP packets to the bounded queue for their association."""

    def __init__(self, receive: Callable[[bytes, tuple[str, int]], None]) -> None:
        self.receive = receive

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) <= MAX_PACKET:
            self.receive(data, addr)


def enqueue(queue: asyncio.Queue[bytes], data: bytes) -> None:
    """Apply datagram loss rather than unbounded buffering under congestion."""
    if not queue.full():
        queue.put_nowait(data)


async def serve(c: dict[str, Any]) -> None:
    """Serve the single authenticated UDP destination configured by the owner."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("cert.pem", "key.pem")
    ctx.set_alpn_protocols(["http/1.1"])
    active = 0

    async def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal active
        active += 1
        try:
            if active > MAX_SESSIONS:
                return
            line, fields = await headers(reader)
            parts = line.split()
            if not hmac.compare_digest(
                fields.get("proxy-authorization", "").encode(), credential(c).encode()
            ):
                writer.write(
                    b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="routes"\r\nContent-Length: 0\r\n\r\n'
                )
            elif (
                len(parts) != 3
                or parts[0] != "GET"
                or parts[2] != "HTTP/1.1"
                or urlsplit(parts[1]).path != endpoint(c)
                or not upgrade(fields)
            ):
                writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            else:
                q: asyncio.Queue[bytes] = asyncio.Queue(32)
                transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: Udp(lambda d, _a: enqueue(q, d)),
                    remote_addr=(c["target"], c["target_port"]),
                )
                try:
                    writer.write(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n\r\n"
                    )
                    await writer.drain()
                    await exchange(reader, writer, q, transport.sendto)
                finally:
                    transport.close()
            await writer.drain()
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()
            active -= 1

    async with await asyncio.start_server(
        accept,
        c.get("listen", "0.0.0.0"),
        c["port"],
        ssl=ctx,
        limit=16384,
        ssl_handshake_timeout=10,
    ) as srv:
        await srv.serve_forever()


async def connect(c: dict[str, Any]) -> None:
    """Create a separate authenticated capsule stream for each local UDP source."""
    ctx = ssl.create_default_context(cadata=c.get("certificate") or None)
    ctx.set_alpn_protocols(["http/1.1"])
    sessions: dict[tuple[str, int], asyncio.Queue[bytes]] = {}
    jobs: set[asyncio.Task[None]] = set()

    async def session(addr: tuple[str, int], q: asyncio.Queue[bytes]) -> None:
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    c["host"], c["port"], ssl=ctx, server_hostname=c["name"], limit=16384
                ),
                12,
            )
            name = c["name"]
            authority = (f"[{name}]" if ":" in name else name) + ":" + str(c["port"])
            path = "https://" + authority + endpoint(c)
            request = f"GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\nCapsule-Protocol: ?1\r\n"
            if c["password"]:
                request += "Proxy-Authorization: " + credential(c) + "\r\n"
            writer.write((request + "\r\n").encode("ascii"))
            await writer.drain()
            status, fields = await headers(reader)
            if status.split()[1:2] != ["101"] or not upgrade(fields):
                raise ValueError("MASQUE upgrade rejected")
            await exchange(reader, writer, q, lambda d: transport.sendto(d, addr))
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            if writer:
                writer.close()
            sessions.pop(addr, None)

    def receive(data: bytes, addr: tuple[str, int]) -> None:
        if addr not in sessions:
            if len(sessions) >= MAX_SESSIONS:
                return
            sessions[addr] = asyncio.Queue(32)
            job = asyncio.create_task(session(addr, sessions[addr]))
            jobs.add(job)
            job.add_done_callback(jobs.discard)
        enqueue(sessions[addr], data)

    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: Udp(receive), local_addr=("127.0.0.1", c["local_port"])
    )
    try:
        await asyncio.Future()
    finally:
        transport.close()
        for job in jobs:
            job.cancel()


if __name__ == "__main__":
    settings = json.loads(
        sys.stdin.buffer.read() if sys.argv[2] == "-" else Path(sys.argv[2]).read_bytes()
    )
    asyncio.run((serve if sys.argv[1] == "server" else connect)(settings))
