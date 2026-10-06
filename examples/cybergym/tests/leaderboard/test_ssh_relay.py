# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Controller loopback relay over a real TCP exchange."""

from __future__ import annotations

import socket
import socketserver
import threading

import pytest
from nooa_cybergym.leaderboard.ssh_relay import LoopbackRelay


class _Echo(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        with self.request:
            while payload := self.request.recv(65536):
                self.request.sendall(payload[::-1])


def test_relay_forwards_both_directions_and_releases_port() -> None:
    upstream = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Echo)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    try:
        port = upstream.server_address[1]
        relay = LoopbackRelay.start("127.0.0.1", port)
        local_port = relay.port
        try:
            with socket.create_connection(("127.0.0.1", local_port), timeout=2) as client:
                client.settimeout(2)
                client.sendall(b"hello")
                assert client.recv(5) == b"olleh"
        finally:
            relay.close()
        replacement = LoopbackRelay.start("127.0.0.1", port, local_port=local_port)
        replacement.close()
    finally:
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=2)


def test_relay_refuses_hostnames_and_non_loopback_listener() -> None:
    with pytest.raises(ValueError, match="literal"):
        LoopbackRelay.start("host.docker.internal", 2222)
    with pytest.raises(ValueError, match="loopback"):
        LoopbackRelay.start("127.0.0.1", 2222, listen_host="0.0.0.0")
