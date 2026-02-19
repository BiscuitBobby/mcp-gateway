from config import settings # always import first for telemetry
from gateway.models import load_config, mount_proxy
from fastapi import FastAPI
from fastmcp import FastMCP
from pathlib import Path
import asyncio
import uvicorn
import json

class ServerRoutes:
    _file = Path(f"{settings.temp_dir}/server_routes.json")

    def __new__(cls):
        if not hasattr(cls, 'inst'):
            cls.inst = super().__new__(cls)
            cls.inst._data = cls._load()
        return cls.inst

    @classmethod
    def _load(cls):
        if cls._file.exists():
            with open(cls._file, "r") as f:
                return json.load(f)
        return {}

    def _save(self):
        with open(self._file, "w") as f:
            json.dump(self._data, f)

    def add(self, alias: str, port: int):
        self._data[alias] = port
        self._save()

    def get(self, alias: str):
        return self._data.get(alias)

    def all(self):
        return dict(self._data)

    def remove(self, alias: str):
        if alias in self._data:
            del self._data[alias]
            self._save()
            return True
        return False

    def clear(self):
        self._data.clear()
        self._save()


_running_servers: dict[str, tuple[uvicorn.Server, asyncio.Task]] = {}


def create_app(proxy, alias):
    mcp_app = proxy.http_app(path="/")
    app = FastAPI(lifespan=mcp_app.lifespan)
    app.mount(f"/v1/{alias}", mcp_app)
    return app


async def start_server(alias: str, cfg: dict, port: int):
    sd = ServerRoutes()
    proxy = FastMCP(name=alias)
    await mount_proxy(proxy, alias, cfg)
    app = create_app(proxy, alias)

    uvi_cfg = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
    server = uvicorn.Server(uvi_cfg)

    task = asyncio.create_task(server.serve(), name=f"server-{alias}")
    _running_servers[alias] = (server, task)
    sd.add(alias, port)
    print(f"Started proxy '{alias}' on port {port}")


async def stop_server(alias: str):
    sd = ServerRoutes()
    entry = _running_servers.pop(alias, None)
    if entry is None:
        return

    server, task = entry
    server.should_exit = True          # signals uvicorn to stop
    try:
        await asyncio.wait_for(task, timeout=10)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        task.cancel()

    sd.remove(alias)
    print(f"Stopped proxy '{alias}'")


async def refresh():
    """
    Reload the config and reconcile running servers:
      - Stop servers whose alias is no longer in the config.
      - Start servers for aliases that are new to the config.
      - Leave unchanged aliases alone.
    """
    sd = ServerRoutes()
    new_config = load_config()

    current_aliases = set(_running_servers.keys())
    new_aliases = set(new_config.keys())

    to_stop = current_aliases - new_aliases
    to_start = new_aliases - current_aliases

    # Stop removed servers
    await asyncio.gather(*[stop_server(alias) for alias in to_stop])

    # Determine next available port (above the highest currently used, or base)
    used_ports = set(sd.all().values())
    base_port = 8001
    def next_free_port():
        port = base_port
        while port in used_ports:
            port += 1
        used_ports.add(port)
        return port

    # Start new servers
    await asyncio.gather(*[
        start_server(alias, new_config[alias], next_free_port())
        for alias in to_start
    ])

    print(f"Refresh complete. Running: {sd.all()}")


async def run_all():
    base_port = 8001
    config = load_config()
    sd = ServerRoutes()
    sd.clear()

    await asyncio.gather(*[
        start_server(alias, cfg, base_port + idx)
        for idx, (alias, cfg) in enumerate(config.items())
    ])

    print(sd.all())

    # Keep the event loop alive while servers run
    await asyncio.gather(*[task for _, task in _running_servers.values()])


if __name__ == "__main__":
    asyncio.run(run_all())