"""
server.py — FastAPI bridge between the C sniffer's UDP stream and the browser.

  C sniffer --UDP/JSON:5005--> [asyncio datagram] --> Collector
                                                          |
                              WebSocket /ws  <-- 3 Hz snapshot broadcast

Run from this directory:
    uvicorn server:app --host 127.0.0.1 --port 8080
or simply:
    python server.py

Note: only one consumer can bind UDP 5005 at a time, so run EITHER the rich TUI
(python/app.py) OR this web dashboard, not both.
"""

import asyncio
import json
import contextlib
import os
import sys
from pathlib import Path

# Allow `python /path/to/web/server.py` from any working directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from collector import Collector

UDP_IP = "127.0.0.1"
UDP_PORT = 5005
PUSH_HZ = 3

STATIC = Path(__file__).parent / "static"

collector = Collector()
ws_clients: set[WebSocket] = set()


class _UDPProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        try:
            collector.ingest(json.loads(data.decode("utf-8", "replace")))
        except (ValueError, json.JSONDecodeError):
            pass  # ignore malformed datagrams


async def _broadcaster():
    """Push one aggregated snapshot to all browsers at a fixed cadence."""
    while True:
        await asyncio.sleep(1 / PUSH_HZ)
        if not ws_clients:
            continue
        payload = json.dumps(collector.snapshot())
        dead = set()
        for ws in ws_clients:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)
        ws_clients.difference_update(dead)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        _UDPProtocol, local_addr=(UDP_IP, UDP_PORT))
    task = asyncio.create_task(_broadcaster())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        transport.close()


app = FastAPI(title="WiFi Analyzer", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def index():
    return (STATIC / "index.html").read_text()


@app.get("/api/state")
async def state():
    return collector.snapshot()


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    ws_clients.add(ws)
    try:
        # We don't expect client messages; this just detects disconnect.
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        ws_clients.discard(ws)


app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)
