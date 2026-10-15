"""Versioned, capability-scoped plugin discovery and lifecycle."""

from __future__ import annotations

import importlib.metadata
import re
from dataclasses import dataclass, field
from typing import Any, Protocol


API_VERSION = "1.0"
PLUGIN_GROUP = "angerona.plugins"
_NAME = re.compile(r"^[a-z][a-z0-9_.-]{1,63}$")
ALLOWED_CAPABILITIES = {
    "analyzer", "loader", "processor", "execution_provider", "rule_provider",
    "symbol_provider", "exporter", "reporter",
}


@dataclass(frozen=True)
class PluginManifest:
    name: str
    version: str
    api_version: str
    capabilities: tuple[str, ...]
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.name):
            raise ValueError("invalid plugin name")
        if not re.fullmatch(r"\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?", self.version):
            raise ValueError("plugin version must be semantic")
        if any(capability not in ALLOWED_CAPABILITIES for capability in self.capabilities):
            raise ValueError("plugin requests an unknown capability")
        if len(self.capabilities) != len(set(self.capabilities)):
            raise ValueError("plugin capabilities must be unique")

    def compatible(self, host_api: str = API_VERSION) -> bool:
        required_major, required_minor = (int(value) for value in self.api_version.split(".")[:2])
        host_major, host_minor = (int(value) for value in host_api.split(".")[:2])
        return required_major == host_major and required_minor <= host_minor


@dataclass(frozen=True)
class PluginContext:
    workspace: str | None = None
    services: dict[str, Any] = field(default_factory=dict, compare=False)

    def service(self, name: str) -> Any:
        if name not in self.services:
            raise KeyError(f"plugin service is unavailable: {name}")
        return self.services[name]


class Plugin(Protocol):
    manifest: PluginManifest
    def activate(self, context: PluginContext) -> None: ...
    def deactivate(self) -> None: ...


class PluginRegistry:
    def __init__(self, *, api_version: str = API_VERSION) -> None:
        self.api_version = api_version
        self._plugins: dict[str, Plugin] = {}
        self._active: set[str] = set()

    def register(self, plugin: Plugin) -> None:
        manifest = plugin.manifest
        if not manifest.compatible(self.api_version):
            raise ValueError(
                f"plugin {manifest.name} requires API {manifest.api_version}; host is {self.api_version}"
            )
        if manifest.name in self._plugins:
            raise ValueError(f"duplicate plugin name: {manifest.name}")
        self._plugins[manifest.name] = plugin

    def discover(self) -> list[dict[str, str]]:
        failures: list[dict[str, str]] = []
        entry_points = importlib.metadata.entry_points()
        selected = entry_points.select(group=PLUGIN_GROUP) if hasattr(entry_points, "select") else entry_points.get(PLUGIN_GROUP, [])
        for entry_point in selected:
            try:
                candidate = entry_point.load()
                plugin = candidate() if isinstance(candidate, type) else candidate
                self.register(plugin)
            except Exception as exc:  # noqa: BLE001 - one bad plugin must not break discovery
                failures.append({"entry_point": entry_point.name, "error": str(exc)})
        return failures

    def activate(self, name: str, context: PluginContext | None = None) -> None:
        if name not in self._plugins:
            raise KeyError(f"unknown plugin: {name}")
        if name in self._active:
            return
        self._plugins[name].activate(context or PluginContext())
        self._active.add(name)

    def deactivate(self, name: str) -> None:
        if name not in self._active:
            return
        self._plugins[name].deactivate()
        self._active.remove(name)

    def by_capability(self, capability: str) -> list[Plugin]:
        if capability not in ALLOWED_CAPABILITIES:
            raise ValueError("unknown plugin capability")
        return sorted(
            (plugin for plugin in self._plugins.values() if capability in plugin.manifest.capabilities),
            key=lambda plugin: plugin.manifest.name,
        )

    def status(self) -> list[dict[str, Any]]:
        return [{
            "name": name,
            "version": plugin.manifest.version,
            "api_version": plugin.manifest.api_version,
            "capabilities": list(plugin.manifest.capabilities),
            "active": name in self._active,
        } for name, plugin in sorted(self._plugins.items())]
