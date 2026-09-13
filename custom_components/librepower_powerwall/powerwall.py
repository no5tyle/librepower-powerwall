# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 LibrePower contributors
# Full license: /LICENSE. Third-party exception (this file is NOT it): /NOTICE.

"""Local Powerwall access via pypowerwall's TEDAPI transport.

Design note — read this before assuming "no cloud" applies to everything
--------------------------------------------------------------------------
**Telemetry is genuinely cloud-free.** Gateway-password TEDAPI mode needs only
the password printed on the Powerwall. No Tesla account, no Fleet API
registration, no cloud pairing.

**Control is not.** Every write — backup reserve, operation mode, grid export
rule, islanding — requires pypowerwall's "v1r" transport, which needs an
RSA key registered through Tesla's Fleet API (a one-time cloud handshake,
physically confirmed by toggling the DC isolator). This is not a limitation
of this integration; it's how Tesla's local protocol is designed. PowerSync
goes through the identical Fleet API pairing step for the same reason.

Practical effect: with gateway-password-only setup, LibrePower can plan and
display a schedule (v0.1's actual scope) but any control write raises
``PowerwallV1rRequiredError``. Adding v1r support means adding the RSA
pairing flow to config_flow.py — real scope, not yet built.

pypowerwall (MIT, jasonacox) already implements both transports, so we wrap
it rather than reimplementing TEDAPI or the v1r signing. Everything here is a
thin adapter: blocking pypowerwall calls are pushed to the executor because
Home Assistant's event loop must never block.

Reachability
------------
The gateway serves TEDAPI on its own WiFi AP subnet (192.168.91.1). The HA host
needs a route to it — either joined to the gateway's WiFi, or a static route.
PW3 on wired LAN is a different transport (bearer auth); see `AUTH_MODE` below
when adding that.

This is a battery adapter for LibrePower core
------------------------------------------------
This repo depends on and imports types from ``librepower`` core (GPLv3) - see
this repo's own LICENSE and NOTICE for what that means for this file's
license. The exceptions below subclass core's generic ``battery.py`` types so
core's coordinator can catch them without knowing this adapter exists.
"""
from __future__ import annotations

import logging
from typing import Any

# Cross-repo import: relies on custom_components being a shared namespace
# package and this integration's manifest.json declaring
# "dependencies": ["librepower"], which guarantees core loads first. See
# librepower/battery.py's own docstring for the honest limits of this
# pattern - it works today, it is not an HA-blessed stable API.
from custom_components.librepower.battery import (
    BatteryAuthError,
    BatteryCapabilities,
    BatteryControlUnavailableError,
    BatteryError,
    BatteryReadOnlyError,
    BatterySnapshot,
)

_LOGGER = logging.getLogger(__name__)


class PowerwallError(BatteryError):
    """Base error for local Powerwall access."""


class PowerwallAuthError(PowerwallError, BatteryAuthError):
    """Gateway rejected the supplied password."""


class PowerwallUnreachableError(PowerwallError):
    """Gateway could not be contacted at the configured host."""


class PowerwallReadOnlyError(PowerwallError, BatteryReadOnlyError):
    """A write was attempted while running in shadow mode."""


class PowerwallV1rRequiredError(PowerwallError, BatteryControlUnavailableError):
    """A write was rejected because the connection lacks v1r transport.

    Raised when pypowerwall returns a falsy result from a write call rather
    than raising — its own signal that the RSA-signed channel isn't present.
    Gateway-password-only TEDAPI can read telemetry with zero cloud
    dependency, but every write (reserve, mode, export rule, islanding)
    needs v1r, which needs a one-time RSA key registered through Tesla's
    Fleet API. There is currently no way around this on Tesla hardware.
    """


class PowerwallClient:
    """Adapter over pypowerwall for local telemetry and control."""

    def __init__(
        self,
        hass,
        host: str,
        gateway_password: str,
        capacity_wh: float,
        max_charge_w: float,
        max_discharge_w: float,
        read_only: bool = True,
    ) -> None:
        self._hass = hass
        self._host = host
        self._gw_pwd = gateway_password
        self._pw: Any | None = None
        # User-entered during this adapter's own setup - pypowerwall has no
        # API to read nameplate capacity from the device (checked; there
        # isn't one), so this can't be auto-detected. See battery.py's
        # docstring in core for why this lives here rather than in core.
        self._capacity_wh = capacity_wh
        self._max_charge_w = max_charge_w
        self._max_discharge_w = max_discharge_w
        # Enforced at the lowest level on purpose. A guard further up could be
        # bypassed by a future service handler calling the client directly;
        # here, no write can escape regardless of who calls it.
        self._read_only = read_only

    @property
    def read_only(self) -> bool:
        return self._read_only

    async def async_get_capabilities(self) -> BatteryCapabilities:
        """Report this Powerwall's physical limits to core.

        Just returns what was entered at setup - see the constructor's note
        on why this isn't read live from the device.
        """
        return BatteryCapabilities(
            capacity_wh=self._capacity_wh,
            max_charge_w=self._max_charge_w,
            max_discharge_w=self._max_discharge_w,
        )

    # -- lifecycle ------------------------------------------------------------

    async def async_connect(self) -> None:
        """Construct the pypowerwall client and verify we can talk to it."""
        self._pw = await self._hass.async_add_executor_job(self._build_client)
        # A snapshot is the real connectivity test; construction alone is lazy.
        await self.async_get_snapshot()

    def _build_client(self) -> Any:
        """Blocking. Runs in executor."""
        try:
            import pypowerwall
        except ImportError as err:  # pragma: no cover - dependency declared
            raise PowerwallError("pypowerwall is not installed") from err

        try:
            return pypowerwall.Powerwall(
                host=self._host,
                gw_pwd=self._gw_pwd,
                # No email/password: we are explicitly not using cloud auth.
                email="",
                password="",
                # Local TEDAPI only. Never silently fall back to the cloud.
                cloudmode=False,
                timezone=str(self._hass.config.time_zone),
            )
        except Exception as err:
            raise self._translate(err) from err

    async def async_close(self) -> None:
        """Release the underlying session, if the library exposes one."""
        if self._pw is None:
            return
        close = getattr(self._pw, "close", None)
        if callable(close):
            await self._hass.async_add_executor_job(close)
        self._pw = None

    # -- reads ----------------------------------------------------------------

    async def async_get_snapshot(self) -> BatterySnapshot:
        """Fetch one live snapshot of the system."""
        if self._pw is None:
            raise PowerwallError("Powerwall client is not connected")
        return await self._hass.async_add_executor_job(self._read_snapshot)

    def _read_snapshot(self) -> BatterySnapshot:
        """Blocking. Runs in executor."""
        pw = self._pw
        try:
            # ``power()`` returns the aggregate site/battery/load/solar flows.
            flows = pw.power() or {}
            level = pw.level()
        except Exception as err:
            raise self._translate(err) from err

        if level is None:
            raise PowerwallError("Gateway returned no state-of-charge")

        # pypowerwall reports grid as "site" and battery as "battery", with
        # battery negative when charging — same convention we expose.
        return BatterySnapshot(
            soc=self._normalise_soc(level),
            solar_w=float(flows.get("solar") or 0.0),
            battery_w=float(flows.get("battery") or 0.0),
            grid_w=float(flows.get("site") or 0.0),
            load_w=float(flows.get("load") or 0.0),
            grid_connected=self._read_grid_status(pw),
        )

    @staticmethod
    def _normalise_soc(level: float) -> float:
        """pypowerwall reports percentage; we work in 0-1 throughout."""
        value = float(level)
        return max(0.0, min(1.0, value / 100.0 if value > 1.0 else value))

    @staticmethod
    def _read_grid_status(pw: Any) -> bool:
        """Best-effort islanding check; never fail a snapshot over it."""
        try:
            status = pw.grid_status()
        except Exception:  # noqa: BLE001 - diagnostic only
            return True
        if isinstance(status, str):
            return status.upper() in ("UP", "SYSTEM_GRID_CONNECTED")
        return bool(status)

    # -- writes ---------------------------------------------------------------

    async def async_set_backup_reserve(self, reserve: float) -> None:
        """Set the backup reserve (0-1).

        This is the primary control lever: raising the reserve above current SOC
        holds the battery, lowering it permits discharge. It is deliberately the
        only write the optimiser needs for the common case.

        Requires v1r (see module docstring). Against a gateway-password-only
        connection this raises ``PowerwallV1rRequiredError`` rather than
        silently no-op'ing.
        """
        if not 0.0 <= reserve <= 1.0:
            raise ValueError(f"reserve must be 0-1, got {reserve}")
        await self._call_write("set_reserve", reserve * 100.0)

    async def async_set_operation_mode(self, mode: str) -> None:
        """Set the gateway operation mode (e.g. self_consumption, autonomous).

        Requires v1r. See module docstring.
        """
        await self._call_write("set_mode", mode)

    async def async_set_grid_export(self, rule: str) -> None:
        """Set the export rule: 'battery_ok', 'pv_only', or 'never'.

        This is the soft curtailment lever. Setting 'never' blocks all export;
        with nowhere for surplus solar to go, the Gateway curtails production
        rather than overproduce. The site stays grid-connected throughout —
        import still works, this only gates export.

        Requires v1r. See module docstring.
        """
        if rule not in ("battery_ok", "pv_only", "never"):
            raise ValueError(f"Invalid export rule: {rule}")
        await self._call_write("set_grid_export", rule)

    async def async_go_off_grid(self) -> None:
        """Force intentional islanding — hard curtailment of last resort.

        Disconnects from the grid entirely. Solar is throttled to house load
        plus battery charging because there is nowhere else for it to go, same
        underlying mechanism as export='never', but with no import path either.

        This is NOT a routine curtailment tool. It exists for the case
        export='never' cannot reach — e.g. an AC-coupled inverter on a
        different circuit that keeps exporting regardless of the Gateway's
        export rule. Any caller of this needs its own safety gating (SOC
        floor, duration cap) — this method applies none. See PowerSync's
        curtailment_fallback.py for the shape such gating should take
        (independently implemented, not copied — that file is PolyForm
        licensed).

        Requires v1r. See module docstring.
        """
        await self._call_write("go_off_grid")

    async def async_reconnect_grid(self) -> None:
        """Reverse ``async_go_off_grid``. Requires v1r."""
        await self._call_write("reconnect_grid")

    async def _call_write(self, method_name: str, *args: Any) -> None:
        if self._read_only:
            _LOGGER.debug(
                "Shadow mode: suppressed %s%s", method_name, args
            )
            raise PowerwallReadOnlyError(
                "LibrePower is in shadow mode and will not write to the battery. "
                "Enable control in the integration options once no other "
                "integration is managing this Powerwall."
            )
        if self._pw is None:
            raise PowerwallError("Powerwall client is not connected")
        method = getattr(self._pw, method_name, None)
        if not callable(method):
            raise PowerwallError(
                f"This Powerwall backend does not support {method_name}()"
            )

        def _write() -> Any:
            try:
                return method(*args)
            except Exception as err:
                raise self._translate(err) from err

        result = await self._hass.async_add_executor_job(_write)

        # pypowerwall does not raise when the underlying transport rejects a
        # write — set_reserve/set_mode/set_grid_export/go_off_grid all log an
        # error and return None if v1r isn't available, which would otherwise
        # look identical to success. Treat a falsy result as failure.
        if not result:
            raise PowerwallV1rRequiredError(
                f"{method_name}() returned no result. This almost always means "
                "the connection lacks v1r (RSA-signed) transport — battery "
                "control requires the one-time Fleet API key registration; "
                "gateway-password-only mode can read telemetry but cannot "
                "write."
            )

    # -- error mapping --------------------------------------------------------

    @staticmethod
    def _translate(err: Exception) -> PowerwallError:
        """Map library/transport errors onto our own taxonomy.

        pypowerwall raises fairly generic exceptions, so we classify on the
        message. Kept in one place so the config flow can show the user a
        useful reason rather than a stack trace.
        """
        text = str(err).lower()
        if any(k in text for k in ("auth", "password", "403", "unauthorized")):
            return PowerwallAuthError(str(err))
        if any(k in text for k in ("timeout", "unreachable", "refused", "route")):
            return PowerwallUnreachableError(str(err))
        return PowerwallError(str(err))
