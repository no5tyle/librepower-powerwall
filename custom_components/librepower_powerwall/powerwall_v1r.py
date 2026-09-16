# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 LibrePower contributors
# Full license: /LICENSE. Third-party exception (this file is NOT it): /NOTICE.

"""Password-free local Powerwall access via pure v1r (RSA-signed) transport.

Why this exists alongside powerwall.py's pypowerwall-wrapped connection
------------------------------------------------------------------------
pypowerwall's own ``Powerwall``/``TEDAPI`` wrapper classes still require a
non-empty ``password`` even in v1r mode - not because the wire protocol
needs it, but because their own ``connect()`` sequence calls
``POST /api/login/Basic`` to fetch a Bearer token for exactly one purpose:
``GET /tedapi/din``. Every *other* v1r call
(``post_v1r``/``get_config_v1r``/``write_config_v1r``/``send_island_mode``)
sends nothing but ``Content-Type: application/octet-stream`` and an
RSA-signed payload - confirmed by reading PowerSync's independent
``transport.py``, which never touches a password at all.

We already have the DIN - it comes back from Tesla's cloud during pairing
(``pairing.async_get_din``, via an existing Teslemetry config entry's
``get_system_info`` call), the same way PowerSync's own local client
receives it. So the one thing pypowerwall's wrapper needs a password for, we
don't need it for at all: this module talks to
``pypowerwall.tedapi.tedapi_v1r.TEDAPIv1r`` directly, skipping
``login()``/``get_din()`` entirely.

Built entirely on pypowerwall's public names (``TEDAPIv1r``'s public
methods, ``tedapi_pb2``'s protobuf classes, ``queries.get_query``/
``apply_query``) - nothing underscore-prefixed or otherwise private. The
one piece pypowerwall doesn't expose publicly is the DeviceControllerQuery
response's field layout (SOC/power-flows/grid-status/alerts) - that parsing
below is cross-referenced against both pypowerwall's own
``get_device_controller()`` docstring and PowerSync's independent
``client.py``, which agree with each other, but neither this project nor
that cross-reference has been validated against live hardware. Treat this
as "should work, wants field verification on a real PW3" rather than
guaranteed-correct.

PW3 wired-LAN only - matches ``TEDAPIv1r``/pypowerwall's own v1r scope.
"""
from __future__ import annotations

import json
import logging
from typing import Any

_LOGGER = logging.getLogger(__name__)

# Tesla-app-scale (0-100%, what callers pass) to TEDAPI config's raw scale
# (5-100% physical) - reverses pypowerwall's own get_reserve(scale=True)
# formula (see its post_api_operation: "raw = app_percent * 0.95 + 5").
_RESERVE_APP_TO_RAW_SCALE = 0.95
_RESERVE_APP_TO_RAW_OFFSET = 5.0

# control.islanding.customerIslandMode values that mean "still on-grid".
# Anything else (Backup, OffGrid, ...) is treated as islanded.
_GRID_CONNECTED_ISLAND_MODES = frozenset({"OnGrid", "SystemGridConnected"})


class V1rError(Exception):
    """Base error for the pure-v1r transport."""


class V1rUnreachableError(V1rError):
    """Couldn't reach the Gateway, or the RSA key isn't verified yet."""


class V1rSnapshot:
    """One parsed reading from a DeviceControllerQuery response."""

    __slots__ = (
        "alerts",
        "battery_w",
        "grid_connected",
        "grid_w",
        "load_w",
        "soc",
        "solar_w",
    )

    def __init__(
        self,
        soc: float | None,
        solar_w: float,
        battery_w: float,
        grid_w: float,
        load_w: float,
        grid_connected: bool,
        alerts: list[str],
    ) -> None:
        self.soc = soc
        self.solar_w = solar_w
        self.battery_w = battery_w
        self.grid_w = grid_w
        self.load_w = load_w
        self.grid_connected = grid_connected
        self.alerts = alerts


class V1rClient:
    """Pure RSA-signed local Powerwall access - no gateway/customer password.

    A thin, blocking (call via executor - see powerwall.py) wrapper. All the
    hard parts (TLV construction, PKCS1v15+SHA512 signing, RoutableMessage
    protobuf framing) are pypowerwall's ``TEDAPIv1r``, already
    hardware-validated (see its own test suite). This class only builds/
    parses the one query type (DeviceControllerQuery) and the config-write
    payloads for the specific operations powerwall.py needs.
    """

    def __init__(self, host: str, rsa_key_path: str, din: str, timeout: int = 10) -> None:
        self._din = din
        _LOGGER.debug("V1rClient.__init__: host=%s din=%s", host, din)
        # TEDAPIv1r's constructor signature requires a `password` argument,
        # but nothing that matters here ever reads it - see module docstring.
        # login()/get_din() (the only methods that do) are never called.
        from pypowerwall.tedapi.tedapi_v1r import TEDAPIv1r

        self._transport = TEDAPIv1r(
            host=host, password="", rsa_key_path=rsa_key_path, timeout=timeout
        )

    def close(self) -> None:
        _LOGGER.debug("V1rClient.close: entered")
        session = getattr(self._transport, "session", None)
        if session is not None:
            session.close()

    # -- reads ------------------------------------------------------------

    def get_snapshot(self) -> V1rSnapshot:
        """One DeviceControllerQuery, parsed into a snapshot. Blocking."""
        data = self._query(_query_role().DEVICE_CONTROLLER_FULL)
        if data is None:
            raise V1rUnreachableError(
                "No response to DeviceControllerQuery - RSA key may not be "
                "VERIFIED yet, or the Gateway is unreachable at this host"
            )
        snapshot = _parse_snapshot(data)
        _LOGGER.debug(
            "get_snapshot: soc=%s solar_w=%.0f battery_w=%.0f grid_w=%.0f load_w=%.0f grid_connected=%s alerts=%s",
            snapshot.soc,
            snapshot.solar_w,
            snapshot.battery_w,
            snapshot.grid_w,
            snapshot.load_w,
            snapshot.grid_connected,
            snapshot.alerts,
        )
        return snapshot

    def _query(self, role: Any) -> dict[str, Any] | None:
        _LOGGER.debug("_query: entered, role=%s", role)
        from pypowerwall.tedapi import tedapi_pb2
        from pypowerwall.tedapi.queries import apply_query, get_query

        pb = tedapi_pb2.Message()
        pb.message.deliveryChannel = 1
        pb.message.sender.local = 1
        pb.message.recipient.din = self._din
        pb.message.payload.send.num = 2
        pb.message.payload.send.payload.value = 1
        apply_query(pb.message.payload.send, get_query(role))
        pb.tail.value = 1
        # Bare MessageEnvelope bytes (just `.message`, not the full Message
        # wrapper with tail) - what v1r expects, matching pypowerwall's own
        # _envelope_bytes. Serializing pb.message directly is equivalent and
        # simpler since we just built pb ourselves.
        envelope_bytes = pb.message.SerializeToString()

        inner = self._transport.post_v1r(envelope_bytes, self._din)
        if inner is None:
            _LOGGER.debug("_query: post_v1r returned no response")
            return None

        envelope = tedapi_pb2.MessageEnvelope()
        envelope.ParseFromString(inner)
        if not envelope.HasField("payload"):
            _LOGGER.debug("_query: response envelope has no payload field")
            return None
        try:
            result = json.loads(envelope.payload.recv.text)
        except (json.JSONDecodeError, ValueError) as err:
            raise V1rError(f"DeviceControllerQuery returned non-JSON payload: {err}") from err
        _LOGGER.debug("_query: parsed JSON payload OK")
        return result

    def get_reserve(self) -> float | None:
        """Current backup reserve, 0-100 Tesla-app scale - same scale
        set_reserve() takes, and matches pypowerwall's own
        get_reserve(scale=True) exactly (same reversed formula), so
        powerwall.py's generic self._pw.get_reserve() dispatch works
        unchanged regardless of which backend is active. Returns None if
        config.json couldn't be read (e.g. key not yet VERIFIED) rather
        than raising - this is a best-effort read used to remember a value
        before overriding it, not a primary data path.
        """
        config = self._transport.get_config_v1r(self._din)
        if not config:
            _LOGGER.debug("get_reserve: config.json unavailable (key not VERIFIED yet?)")
            return None
        raw = (config.get("site_info") or {}).get("backup_reserve_percent")
        if raw is None:
            _LOGGER.debug("get_reserve: no backup_reserve_percent in config")
            return None
        value = max(0.0, (float(raw) - _RESERVE_APP_TO_RAW_OFFSET) / _RESERVE_APP_TO_RAW_SCALE)
        _LOGGER.debug("get_reserve: raw=%s -> app_percent=%.1f", raw, value)
        return value

    # -- writes -------------------------------------------------------------

    def set_reserve(self, app_percent: float) -> bool:
        """Backup reserve, 0-100 Tesla-app scale (same scale powerwall.py uses)."""
        raw = app_percent * _RESERVE_APP_TO_RAW_SCALE + _RESERVE_APP_TO_RAW_OFFSET
        _LOGGER.debug("set_reserve: app_percent=%.1f -> raw=%.1f", app_percent, raw)
        return self._write_config({"site_info.backup_reserve_percent": raw})

    def set_mode(self, mode: str) -> bool:
        _LOGGER.debug("set_mode: mode=%s", mode)
        return self._write_config({"default_real_mode": mode})

    def set_grid_export(self, mode: str) -> bool:
        if mode not in ("battery_ok", "pv_only", "never"):
            raise ValueError(f"Invalid grid export mode: {mode}")
        _LOGGER.debug("set_grid_export: mode=%s", mode)
        return self._write_config({"site_info.customer_preferred_export_rule": mode})

    def _write_config(self, updates: dict[str, Any]) -> bool:
        _LOGGER.debug("_write_config: updates=%s", updates)
        result = self._transport.write_config_v1r(self._din, updates)
        _LOGGER.debug("_write_config: result=%s", bool(result))
        return bool(result)

    def go_off_grid(self) -> bool:
        """Intentional islanding - same signed command as pypowerwall's go_off_grid()."""
        _LOGGER.debug("go_off_grid: entered")
        result = self._transport.send_island_mode(self._din, mode=6, force=True)
        _LOGGER.debug("go_off_grid: result=%s", bool(result))
        return bool(result)

    def reconnect_grid(self) -> bool:
        _LOGGER.debug("reconnect_grid: entered")
        result = self._transport.send_island_mode(self._din, mode=1)
        _LOGGER.debug("reconnect_grid: result=%s", bool(result))
        return bool(result)


def _query_role():
    from pypowerwall.tedapi.queries import QueryRole

    return QueryRole


def _parse_snapshot(data: dict[str, Any]) -> V1rSnapshot:
    """Cross-referenced against pypowerwall's own get_device_controller()
    docstring and PowerSync's independent client.py - see module docstring
    for the "not hardware-tested by us" caveat.
    """
    control = data.get("control") or {}

    system_status = control.get("systemStatus") or {}
    full_wh = system_status.get("nominalFullPackEnergyWh")
    remaining_wh = system_status.get("nominalEnergyRemainingWh")
    soc = (remaining_wh / full_wh) if full_wh else None

    power_by_location: dict[str, float] = {}
    for meter in control.get("meterAggregates") or []:
        location = meter.get("location")
        if location:
            power_by_location[location] = float(meter.get("realPowerW") or 0.0)

    island_mode = ((control.get("islanding") or {}).get("customerIslandMode"))
    grid_connected = island_mode in _GRID_CONNECTED_ISLAND_MODES if island_mode else True

    alerts = list((control.get("alerts") or {}).get("active") or [])

    return V1rSnapshot(
        soc=soc,
        solar_w=power_by_location.get("solar", 0.0),
        battery_w=power_by_location.get("battery", 0.0),
        grid_w=power_by_location.get("site", 0.0),
        load_w=power_by_location.get("load", 0.0),
        grid_connected=grid_connected,
        alerts=alerts,
    )
