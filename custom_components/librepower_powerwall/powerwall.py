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
from datetime import datetime, timezone
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
        charge_efficiency: float = 0.90,
        discharge_efficiency: float = 0.90,
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
        # Efficiency defaults match core's own pre-measurement defaults -
        # see battery.py for why these are provisional, not measured.
        self._capacity_wh = capacity_wh
        self._max_charge_w = max_charge_w
        self._max_discharge_w = max_discharge_w
        self._charge_efficiency = charge_efficiency
        self._discharge_efficiency = discharge_efficiency
        # Updated by every successful snapshot read; used by async_charge to
        # force-charge without an extra pypowerwall call per write (the
        # Gateway "dislikes hammering" - see UPDATE_INTERVAL_TELEMETRY's own
        # comment in core's const.py for the same concern elsewhere).
        self._last_known_soc: float | None = None
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
            charge_efficiency=self._charge_efficiency,
            discharge_efficiency=self._discharge_efficiency,
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
        soc = self._normalise_soc(level)
        self._last_known_soc = soc
        return BatterySnapshot(
            soc=soc,
            solar_w=float(flows.get("solar") or 0.0),
            battery_w=float(flows.get("battery") or 0.0),
            grid_w=float(flows.get("site") or 0.0),
            load_w=float(flows.get("load") or 0.0),
            timestamp=datetime.now(timezone.utc),
            grid_connected=self._read_grid_status(pw),
            operational_status=self._read_operational_status(pw),
            # pypowerwall has no state-of-health API (checked; there isn't
            # one) - None is the honest answer, not a guess. Revisit if a
            # future pypowerwall release adds one, or if per-block SOH turns
            # out to be derivable from vitals() - not confirmed, not used.
            state_of_health=None,
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

    @staticmethod
    def _read_operational_status(pw: Any) -> str:
        """"ok" if pypowerwall's own alerts() reports nothing outstanding.

        alerts() aggregates real device-reported alerts (falls back to the
        /api/solar_powerwall endpoint on firmware where vitals() isn't
        available) - this is genuine fault reporting, not a placeholder.
        Never fail a snapshot over this being unavailable; "ok" is the safe
        default rather than blocking telemetry over a diagnostic extra.
        """
        try:
            alerts = pw.alerts()
        except Exception:  # noqa: BLE001 - diagnostic only
            return "ok"
        if alerts:
            return "fault"
        return "ok"

    # -- battery disposition channel -------------------------------------

    async def async_charge(self, target_soc: float) -> None:
        """Charge toward target_soc, forcing grid charge if needed.

        Realises core's "charge" intent using Powerwall's actual mechanism:
        setting backup reserve *above current SOC* is what forces the
        Gateway to draw grid power into the battery rather than merely
        permitting it. Core doesn't need to know that's how Powerwall does
        it - it just asked to charge toward a target.

        Requires v1r (see module docstring). Against a gateway-password-only
        connection this raises ``PowerwallV1rRequiredError``.
        """
        if not 0.0 <= target_soc <= 1.0:
            raise ValueError(f"target_soc must be 0-1, got {target_soc}")
        current = self._last_known_soc
        reserve = max(target_soc, current) if current is not None else target_soc
        await self._call_write("set_reserve", reserve * 100.0)

    async def async_discharge(self, target_soc: float) -> None:
        """Permit discharge down to target_soc, for load and/or export.

        Requires v1r. See module docstring.
        """
        if not 0.0 <= target_soc <= 1.0:
            raise ValueError(f"target_soc must be 0-1, got {target_soc}")
        await self._call_write("set_reserve", target_soc * 100.0)

    async def async_hold(self, soc: float) -> None:
        """Pin the battery at soc - no charge, no discharge.

        Requires v1r. See module docstring.
        """
        if not 0.0 <= soc <= 1.0:
            raise ValueError(f"soc must be 0-1, got {soc}")
        await self._call_write("set_reserve", soc * 100.0)

    async def async_release(self) -> None:
        """Stop overriding - return to the Gateway's own automatic behaviour.

        Sets operation mode to self_consumption, Powerwall's native
        automatic mode. Known gap: this does not restore whatever backup
        reserve was configured before LibrePower started controlling it -
        that original value is never captured, so reserve is left wherever
        it currently sits. Worth fixing if this proves to matter in
        practice; not done here because a wrong guess at "the original
        value" would be worse than leaving it alone.

        Requires v1r. See module docstring.
        """
        await self._call_write("set_mode", "self_consumption")

    # -- export policy channel, independent of disposition -----------------

    async def async_curtail_export(self, level: str) -> None:
        """'soft': block export, stay grid-connected. 'strong': islanding.

        Soft sets the Gateway's export rule to 'never' - with nowhere for
        surplus solar to go, the Gateway curtails production internally
        rather than overproduce. Strong forces intentional islanding
        (go_off_grid) - same underlying throttling, but drops the site off
        grid entirely, no import either. This is a last resort for cases
        soft curtailment can't reach (e.g. an AC-coupled inverter on a
        separate circuit that keeps exporting regardless of the Gateway's
        export rule).

        Strong curtailment has NO safety gating of its own here (no SOC
        floor, no duration cap) - see optimiser/MODIFICATIONS.md item 7 in
        core for the gating this needs before being callable from anywhere
        automated. Requires v1r either way. See module docstring.
        """
        if level == "soft":
            await self._call_write("set_grid_export", "never")
        elif level == "strong":
            await self._call_write("go_off_grid")
        else:
            raise ValueError(f"Invalid curtailment level: {level}")

    async def async_allow_export(self) -> None:
        """Reverse curtailment - Tesla's normal default export rule.

        If currently islanded (strong curtailment), this also reconnects to
        grid; if soft-curtailed, this just re-permits export. Requires v1r.
        """
        await self._call_write("reconnect_grid")
        await self._call_write("set_grid_export", "battery_ok")

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
