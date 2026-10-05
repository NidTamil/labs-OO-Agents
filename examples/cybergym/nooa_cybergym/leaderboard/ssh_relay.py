"""Controller-owned loopback TCP relay to one isolated task container.

Docker's internal bridge does not publish host ports. The controller binds
only 127.0.0.1 and forwards an authenticated native SSH client's bytes to
the container's private address; this grants the agent no outbound route.
"""

from __future__ import annotations

import ipaddress
import select
import socket
import socketserver
import threading


def _pump(source: socket.socket, destination: socket.socket, closed: threading.Event) -> None:
    try:
        while not closed.is_set():
            if not select.select([source], [], [], 0.25)[0]:
                continue
            payload = source.recv(65536)
            if not payload:
                break
            destination.sendall(payload)
    except OSError:
        pass
    finally:
        try:
            destination.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class _Forwarder(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server: _RelayServer = self.server  # type: ignore[assignment]
        try:
            upstream = socket.create_connection((server.target_ip, server.target_port), timeout=5.0)
        except OSError:
            return
        with upstream:
            # An idle model/tool session may legitimately last hours. The
            # controller closes both sockets explicitly at task teardown.
            self.request.settimeout(None)
            upstream.settimeout(None)
            pair = (self.request, upstream)
            with server.active_lock:
                server.active.add(pair)
            try:
                forward = threading.Thread(
                    target=_pump,
                    args=(self.request, upstream, server.closed),
                    daemon=True,
                )
                forward.start()
                _pump(upstream, self.request, server.closed)
                forward.join(timeout=1.0)
            finally:
                with server.active_lock:
                    server.active.discard(pair)


class _RelayServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False

    def __init__(self, address: tuple[str, int], target_ip: str, target_port: int):
        self.target_ip = target_ip
        self.target_port = target_port
        self.closed = threading.Event()
        self.active_lock = threading.Lock()
        self.active: set[tuple[socket.socket, socket.socket]] = set()
        super().__init__(address, _Forwarder)


class LoopbackRelay:
    """One relay whose endpoint can be rebound after controller restart."""

    def __init__(self, server: _RelayServer, thread: threading.Thread):
        self._server = server
        self._thread = thread
        self.port = int(server.server_address[1])

    @classmethod
    def start(
        cls,
        target_ip: str,
        target_port: int,
        *,
        local_port: int = 0,
        listen_host: str = "127.0.0.1",
    ) -> LoopbackRelay:
        if listen_host != "127.0.0.1":
            raise ValueError("SSH relay listener must be loopback")
        try:
            target = ipaddress.IPv4Address(target_ip)
        except (ipaddress.AddressValueError, TypeError):
            raise ValueError("SSH relay target must be a literal IPv4 address") from None
        if (
            type(target_port) is not int
            or not 1 <= target_port <= 65535
            or type(local_port) is not int
            or not 0 <= local_port <= 65535
        ):
            raise ValueError("SSH relay port is invalid")
        server = _RelayServer((listen_host, local_port), str(target), target_port)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1})
        thread.daemon = True
        thread.start()
        return cls(server, thread)

    def close(self) -> None:
        if self._server.closed.is_set():
            return
        self._server.closed.set()
        with self._server.active_lock:
            active = tuple(self._server.active)
        for pair in active:
            for connection in pair:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)

    def __enter__(self) -> LoopbackRelay:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
