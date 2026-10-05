"""Stream the scoped Docker gateway into the controller's ASGI model service.

The native client uses a public placeholder, never a controller credential.
Only the Docker peer and a controller-owned admission resolver authenticate a
request. Native agent headers may be observed elsewhere; they grant no role.
"""

from __future__ import annotations

import asyncio
import queue
import threading
import time
from collections.abc import Callable

from .host_boundary_runtime import AdmittedPeer, GatewayReply, GatewayRequest
from .model_gateway import NativeModelGateway
from .model_service import CONNECTION_SCOPE_KEY, ModelHTTPService

PUBLIC_CLIENT_TOKEN = "xeus-container-peer-auth"


class _ActiveCall:
    """Cancellation is requested once; completion means ASGI cleanup finished."""

    def __init__(self, loop, disconnected):
        self.loop = loop
        self.disconnected = disconnected
        self.completed = threading.Event()
        self.cancel_requested = threading.Event()
        self.lock = threading.Lock()
        self.task = None

    def cancel(self):
        with self.lock:
            if self.cancel_requested.is_set() or self.completed.is_set():
                return
            self.cancel_requested.set()
            self.disconnected.set()
            # ASGI's disconnect watcher owns cancellation of gateway.forward.
            # Cancelling the outer service too can interrupt that forward's
            # provider-close/audit finally block with a second cancellation.

    def _cancel_task(self):
        if self.task is not None and not self.task.done():
            self.task.cancel()


class _ResponseStream:
    """Close is effective before iteration and from a socket watcher thread."""

    def __init__(self, output, call):
        self.output, self.call = output, call
        self.closed = threading.Event()

    def __iter__(self):
        return self

    def __next__(self):
        while not self.closed.is_set():
            try:
                message = self.output.get(timeout=0.1)
            except queue.Empty:
                if self.call.completed.is_set():
                    self.close()
                    raise RuntimeError("model stream interrupted") from None
                continue
            if message.get("type") != "http.response.body":
                self.close()
                raise RuntimeError("model stream interrupted")
            chunk = message.get("body", b"")
            if not message.get("more_body", False):
                self.close()
            if chunk:
                return chunk
        raise StopIteration

    def close(self):
        self.closed.set()
        self.call.cancel()


class TaskModelRoute:
    """Own one event loop for all requests sharing a task gateway and budget.

    ``admit_peer`` runs in the controller and returns an opaque admission handle,
    not an agent-supplied role. It must refuse a stopped or unregistered peer.
    Close this object only after the host boundary has stopped serving requests.
    """

    def __init__(
        self,
        gateway: NativeModelGateway,
        task_token: str,
        admit_peer: Callable[[AdmittedPeer], object | None],
    ):
        if (
            not isinstance(gateway, NativeModelGateway)
            or not task_token
            or not callable(admit_peer)
        ):
            raise TypeError("controller gateway, token and peer resolver required")
        self._token = task_token
        self._admit_peer = admit_peer
        self._service = ModelHTTPService(gateway, lambda handle: handle)
        self._loop = asyncio.new_event_loop()
        self._closed = threading.Event()
        self._ready = threading.Event()
        self._active: set[_ActiveCall] = set()
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, name="task-model-route", daemon=True)
        self._thread.start()
        if not self._ready.wait(5):
            raise RuntimeError("model route did not start")

    def _run(self):
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        self._loop.run_forever()
        self._loop.run_until_complete(self._loop.shutdown_asyncgens())
        self._loop.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def __repr__(self):
        return "<TaskModelRoute controller-owned state>"

    def __call__(self, request: GatewayRequest) -> GatewayReply:
        if self._closed.is_set():
            return GatewayReply(503, b'{"error":"model route closed"}')
        if request.endpoint != "model-gateway" or request.method != "POST":
            return GatewayReply(403, b'{"error":"model route denied"}')
        try:
            handle = self._admit_peer(request.peer)
            if handle is None:
                raise ValueError
            headers = []
            for name, value in request.headers:
                lower = name.lower()
                if lower in {"authorization", "x-api-key"}:
                    expected = (
                        "Bearer " + PUBLIC_CLIENT_TOKEN
                        if lower == "authorization"
                        else PUBLIC_CLIENT_TOKEN
                    )
                    if value != expected:
                        raise ValueError
                else:
                    headers.append((lower.encode("ascii"), value.encode("latin-1")))
            headers.append((b"authorization", ("Bearer " + self._token).encode("ascii")))
        except Exception:
            return GatewayReply(403, b'{"error":"model route denied"}')

        path, _, query_string = request.path.partition("?")
        scope = {
            "type": "http",
            "method": request.method,
            "path": path,
            "query_string": query_string.encode("ascii"),
            "headers": headers,
            "extensions": {CONNECTION_SCOPE_KEY: handle},
        }
        output: queue.Queue = queue.Queue(maxsize=8)
        disconnected = request.disconnected or threading.Event()
        call = _ActiveCall(self._loop, disconnected)

        async def execute():
            body_delivered = False

            async def receive():
                nonlocal body_delivered
                if not body_delivered:
                    body_delivered = True
                    return {"type": "http.request", "body": request.body, "more_body": False}
                while not disconnected.is_set():
                    await asyncio.sleep(0.02)
                return {"type": "http.disconnect"}

            async def send(message):
                while not disconnected.is_set():
                    try:
                        output.put_nowait(message)
                        return
                    except queue.Full:
                        await asyncio.sleep(0.01)
                raise asyncio.CancelledError

            try:
                await self._service(scope, receive, send)
            except asyncio.CancelledError:
                raise
            except Exception:
                await send({"type": "stream.abort"})
            finally:
                # A consumer waiting for a first response also needs a terminal
                # signal if cancellation happened before response headers.
                try:
                    output.put_nowait({"type": "stream.finished"})
                except queue.Full:
                    pass

        with self._lock:
            if self._closed.is_set():
                return GatewayReply(503, b'{"error":"model route closed"}')
            self._active.add(call)

            def finished(task):
                # This callback runs only after the actual asyncio Task has
                # finished all provider close/audit finally blocks. A cancelled
                # concurrent Future alone cannot establish that fact.
                try:
                    task.exception()
                except asyncio.CancelledError:
                    pass
                with self._lock:
                    self._active.discard(call)
                call.completed.set()

            def start():
                call.task = self._loop.create_task(execute())
                call.task.add_done_callback(finished)
                if call.cancel_requested.is_set():
                    call._cancel_task()

            self._loop.call_soon_threadsafe(start)

        try:
            deadline = time.monotonic() + 60
            while True:
                if disconnected.is_set() or time.monotonic() >= deadline:
                    raise RuntimeError
                try:
                    first = output.get(timeout=0.1)
                    break
                except queue.Empty:
                    if call.completed.is_set():
                        raise RuntimeError from None
            if first.get("type") != "http.response.start":
                raise RuntimeError
        except Exception:
            call.cancel()
            return GatewayReply(503, b'{"error":"model stream unavailable"}')

        response_headers = tuple(
            (k.decode("ascii"), v.decode("latin-1")) for k, v in first["headers"]
        )
        content_type = dict(response_headers).get("content-type", "application/json")
        return GatewayReply(
            first["status"],
            _ResponseStream(output, call),
            content_type,
            tuple((k, v) for k, v in response_headers if k != "content-type"),
        )

    def close(self):
        if not self._thread.is_alive():
            return
        with self._lock:
            self._closed.set()
            calls = tuple(self._active)
        for call in calls:
            call.cancel()
        deadline = time.monotonic() + 5
        for call in calls:
            if not call.completed.wait(max(0, deadline - time.monotonic())):
                # Keep the loop alive so cleanup/auditing can finish. A later
                # close can retry; do not tear down workers mid-accounting.
                raise RuntimeError("model route request cleanup incomplete")
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            raise RuntimeError("model route shutdown incomplete")
