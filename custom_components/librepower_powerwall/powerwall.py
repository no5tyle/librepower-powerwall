# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 LibrePower contributors
# Full license: /LICENSE. Third-party exception (this file is NOT it): /NOTICE.

"""Local Powerwall access - two connection paths, chosen automatically.

STATUS: only gateway-password mode is currently reachable from
config_flow.py. Pure v1r mode (below) still works correctly given an entry
with ``rsa_key_path``/``din`` already set, but nothing in this repo's UI can
populate those anymore - the only pairing mechanism that ever produced them
(pairing.py's Owner API login) broke when Tesla decommissioned that API in
June 2026. See pairing.py's own docstring for the detail and what reviving
it would need (Fleet API credentials). This branching is left in place
rather than ripped out since it isn't wrong, just currently unreachable.

Design note — two genuinely different ways to talk to the Gateway
--------------------------------------------------------------------------
**Gateway-password mode** (``rsa_key_path``/``din`` absent): wraps
pypowerwall's ``Powerwall`` class. Reads work with just the password printed
on the Powerwall - no Tesla account, no cloud, ever. Writes (backup reserve,
operation mode, grid export rule, islanding) additionally need pypowerwall's
"v1r" transport, which needs an RSA key registered through Tesla (a one-time
cloud handshake, physically confirmed by toggling the DC isolator - see
pairing.py). Registering that key does *not* remove the need for the gateway
password here - pypowerwall's own wrapper uses ``gw_pwd`` for both TEDAPI
reads and (internally, to fetch the Gateway's DIN) v1r writes.

**Pure v1r mode** (``rsa_key_path`` and ``din`` both present - see
powerwall_v1r.py): once pairing.py has registered a key, *and* we already
have the DIN from that same cloud step, the gateway password is never used
for anything, for reads or writes. This is a from-scratch adapter over
pypowerwall's ``TEDAPIv1r`` transport (the actual RSA-signed wire protocol,
which pypowerwall's own tests confirm works with no password at all) rather
than pypowerwall's higher wrapper, specifically to skip the wrapper's
password-only-for-DIN requirement. PW3 wired LAN only - matches
``TEDAPIv1r``'s own scope. See powerwall_v1r.py's docstring for the
"cross-referenced against two independent implementations, not hardware-
tested by us" caveat on its snapshot parsing.

``PowerwallClient`` picks between the two automatically in ``_build_client``
based on whether both ``rsa_key_path`` and ``din`` were supplied; callers
(``__init__.py``, config_flow.py) don't need to know which is active - both
expose the same read/write method names (see ``_call_write``'s generic
dispatch), so a config entry can move from one to the other (by pairing) with
no code change on this end, only a reload.

pypowerwall (MIT, jasonacox) already implements the TEDAPI/v1r wire protocol,
so gateway-password mode wraps it rather than reimplementing anything; pure
v1r mode reuses its ``TEDAPIv1r`` signing class but builds its own queries
using only pypowerwall's public names (see powerwall_v1r.py). Both paths push
blocking calls to the executor - Home Assistant's event loop must never
block.

Reachability
------------
Gateway-password mode's default host, 192.168.91.1, is the Gateway's own WiFi
AP subnet; the HA host needs a route to it — either joined to the gateway's
WiFi, or a static route. Pure v1r mode connects to whatever host is
configured directly (typically the Gateway's regular LAN IP) - no AP join
needed once paired.

This is a battery adapter for LibrePower core
------------------------------------------------
This repo depends on and imports types from ``librepower`` core (GPLv3) - see
this repo's own LICENSE and NOTICE for what that means for this file's
license. The exceptions below subclass core's generic ``battery.py`` types so
core's coordinator can catch them without knowing this adapter exists.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, timezone
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

# Strong-curtailment (islanding) safety gate defaults - see
# PowerwallIslandingBlockedError. User-configurable via this integration's
# options flow (config_flow.py's LibrePowerPowerwallOptionsFlow); these are
# the fallback when nothing's been configured there yet, and what a direct
# PowerwallClient construction (e.g. a test) gets if it doesn't override
# these constructor params itself.
DEFAULT_MIN_SOC_FOR_ISLANDING = 0.30
DEFAULT_MAX_ISLANDING_HOURS_PER_DAY = 4.0


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


class PowerwallIslandingBlockedError(PowerwallError, BatteryControlUnavailableError):
    """Strong curtailment (intentional islanding) was refused by this
    adapter's own safety gate - not something Tesla/pypowerwall rejected.

    Two independent guards in ``async_curtail_export``, either one enough to
    block:
      - SOC floor: refused if current SOC is below ``min_soc_for_islanding``,
        *or unknown* - fails closed rather than assuming it's safe.
      - Daily duration cap: refused once today's cumulative intentional-
        islanding time reaches ``max_islanding_hours_per_day``.

    Neither guard exists in pypowerwall or the Gateway itself - Tesla's
    ``go_off_grid()`` will happily disconnect at 1% SOC and stay islanded
    indefinitely if asked; while islanded, the home runs on solar + battery
    alone, so a depleted battery means the home loses power until
    ``reconnect_grid()`` succeeds. This is why core's
    ``optimiser/MODIFICATIONS.md`` item 7 flagged strong curtailment as
    unsafe to call from anywhere automated until gated.
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
        rsa_key_path: str | None = None,
        din: str | None = None,
        min_soc_for_islanding: float = DEFAULT_MIN_SOC_FOR_ISLANDING,
        max_islanding_hours_per_day: float = DEFAULT_MAX_ISLANDING_HOURS_PER_DAY,
    ) -> None:
        self._hass = hass
        self._host = host
        self._gw_pwd = gateway_password
        # Path to a v1r private key file registered via pairing.py, and the
        # Gateway's DIN (also from pairing.py's cloud step). Both present ->
        # pure password-free v1r transport (powerwall_v1r.py); either absent
        # -> the pypowerwall-wrapped gateway-password connection below. See
        # this module's docstring for why pairing alone (rsa_key_path with no
        # din) isn't a valid state in practice - pairing.py always stores
        # both together.
        self._rsa_key_path = rsa_key_path
        self._din = din
        self._is_v1r = bool(rsa_key_path and din)
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
        # Captured in async_connect(), before this adapter ever writes to
        # reserve - see async_release()'s use of it.
        self._original_reserve_percent: float | None = None

        # -- strong-curtailment (islanding) safety gate --------------------
        # See PowerwallIslandingBlockedError. State is in-memory only: an HA
        # restart mid-islanding loses track of how long we've already been
        # disconnected today, resetting the daily counter early - a known
        # gap (persisting it would need HA's storage helpers, not done here)
        # rather than a reason not to have the gate at all.
        self._min_soc_for_islanding = min_soc_for_islanding
        self._max_islanding_hours_per_day = max_islanding_hours_per_day
        self._islanding_started_at: datetime | None = None
        self._islanding_seconds_today: float = 0.0
        self._islanding_day: date | None = None

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
        if not self._read_only:
            # Remember whatever reserve is already set, *before* this
            # adapter ever writes to it, so async_release() can restore it
            # later instead of leaving reserve wherever LibrePower's last
            # write happened to put it. Best-effort: a live reload (this
            # runs on every connect, including ones triggered by core's own
            # control_enabled/backup_reserve changing - see __init__.py's
            # live-reload listener) is exactly when "whatever's there now"
            # is the right thing to capture, and a read failure here isn't
            # fatal to setup - async_release() just has nothing to restore.
            try:
                self._original_reserve_percent = await self._hass.async_add_executor_job(
                    self._pw.get_reserve
                )
            except Exception as err:  # noqa: BLE001 - best-effort, never fatal
                _LOGGER.debug("Could not read current reserve to remember it: %s", err)
                self._original_reserve_percent = None

    def _build_client(self) -> Any:
        """Blocking. Runs in executor."""
        if self._is_v1r:
            try:
                from .powerwall_v1r import V1rClient

                return V1rClient(
                    host=self._host, rsa_key_path=self._rsa_key_path, din=self._din
                )
            except Exception as err:
                raise self._translate(err) from err

        try:
            import pypowerwall
        except ImportError as err:  # pragma: no cover - dependency declared
            raise PowerwallError("pypowerwall is not installed") from err

        try:
            pw = pypowerwall.Powerwall(
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

        # pypowerwall's own connect() fallback (local -> fleetapi -> cloud)
        # does NOT raise when every mode fails - it only logs internally
        # (e.g. "Access Denied: Check your Gateway Password" from a rejected
        # TEDAPI login, or a network-level failure) and leaves `pw.client`
        # None, so the try/except above never fires for this case. Left
        # unchecked, the first sign of trouble used to be async_get_snapshot's
        # generic "Gateway returned no state-of-charge" once every read
        # silently came back empty - true, but unhelpful, and not classified
        # as an auth/unreachable error by _translate since there's no
        # exception text to pattern-match on. Checking here instead gives a
        # single, clear failure point with a pointer at the real reason,
        # which is in the Home Assistant log (pypowerwall's own logger),
        # not in anything this exception can carry - pypowerwall doesn't
        # expose the swallowed per-mode reasons on the object itself.
        if getattr(pw, "client", None) is None:
            # Deliberately the plain base class, not PowerwallAuthError or
            # PowerwallUnreachableError - pypowerwall gives us no signal here
            # for which of those it actually was (see comment above), and a
            # wrong guess would send the user chasing the wrong fix. The
            # config flow's generic PowerwallError handler still surfaces
            # this exact message via _LOGGER.error, which is what matters.
            raise PowerwallError(
                "Could not connect to the Powerwall Gateway - every mode "
                "pypowerwall tried (local/fleetapi/cloud) failed. This "
                "usually means the Gateway password is wrong, or the host "
                "isn't reachable from Home Assistant. Check the Home "
                "Assistant log for pypowerwall's own more specific reason "
                "(e.g. 'Access Denied' means the password was rejected)."
            )
        return pw

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
        if self._is_v1r:
            return self._read_snapshot_v1r()

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

    def _read_snapshot_v1r(self) -> BatterySnapshot:
        """Blocking. Runs in executor. See powerwall_v1r.py's module docstring
        for the "cross-referenced, not hardware-tested by us" caveat on the
        DeviceControllerQuery field parsing this depends on.
        """
        from .powerwall_v1r import V1rError

        try:
            snapshot = self._pw.get_snapshot()
        except V1rError as err:
            raise self._translate(err) from err

        # meterAggregates has no direct SOC-unavailable signal distinct from
        # "the query itself failed" (which raises above) - fall back to the
        # last known reading rather than reporting a fabricated 0%/100%.
        soc = snapshot.soc if snapshot.soc is not None else (self._last_known_soc or 0.5)
        self._last_known_soc = soc
        return BatterySnapshot(
            soc=soc,
            solar_w=snapshot.solar_w,
            battery_w=snapshot.battery_w,
            grid_w=snapshot.grid_w,
            load_w=snapshot.load_w,
            timestamp=datetime.now(timezone.utc),
            grid_connected=snapshot.grid_connected,
            operational_status="fault" if snapshot.alerts else "ok",
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
        automatic mode, then restores whatever backup reserve was in place
        before this adapter's first write this connection (captured in
        async_connect() - see its own comment). If nothing was captured
        (the read failed, or this is a read-only/shadow-mode connection
        that never wrote in the first place), reserve is left wherever it
        currently sits rather than guessing - a wrong guess would be worse
        than doing nothing.

        Requires v1r. See module docstring.
        """
        await self._call_write("set_mode", "self_consumption")
        if self._original_reserve_percent is not None:
            await self._call_write("set_reserve", self._original_reserve_percent)

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

        Strong curtailment is gated by an SOC floor and a daily duration cap
        (see PowerwallIslandingBlockedError) - Tesla's go_off_grid() itself
        has neither. Requires v1r either way. See module docstring.
        """
        if level == "soft":
            await self._call_write("set_grid_export", "never")
        elif level == "strong":
            self._check_islanding_allowed()
            await self._call_write("go_off_grid")
            self._islanding_started_at = datetime.now(timezone.utc)
        else:
            raise ValueError(f"Invalid curtailment level: {level}")

    async def async_allow_export(self) -> None:
        """Reverse curtailment - Tesla's normal default export rule.

        If currently islanded (strong curtailment), this also reconnects to
        grid; if soft-curtailed, this just re-permits export. Requires v1r.
        """
        await self._call_write("reconnect_grid")
        await self._call_write("set_grid_export", "battery_ok")
        self._record_islanding_ended()

    # -- strong-curtailment (islanding) safety gate ------------------------

    def _check_islanding_allowed(self) -> None:
        """Refuse to island if the SOC is too low (or unknown) or today's
        duration cap is already used up. See PowerwallIslandingBlockedError.
        """
        if self._last_known_soc is None:
            raise PowerwallIslandingBlockedError(
                "Refusing to island: current SOC is unknown (no snapshot "
                "read yet). Failing closed rather than assuming it's safe."
            )
        if self._last_known_soc < self._min_soc_for_islanding:
            raise PowerwallIslandingBlockedError(
                f"Refusing to island: SOC {self._last_known_soc:.0%} is below "
                f"the minimum {self._min_soc_for_islanding:.0%} required to "
                "intentionally disconnect from the grid."
            )
        used_hours = self._islanding_hours_used_today()
        if used_hours >= self._max_islanding_hours_per_day:
            raise PowerwallIslandingBlockedError(
                f"Refusing to island: today's cap of "
                f"{self._max_islanding_hours_per_day:.1f}h of intentional "
                f"islanding is already used ({used_hours:.1f}h). Reconnect "
                "and wait for tomorrow, or raise the cap if this is "
                "intentional."
            )

    def _islanding_hours_used_today(self) -> float:
        """Cumulative intentional-islanding time today, including any
        session currently in progress (computed live, not just what's been
        recorded so far by _record_islanding_ended).
        """
        self._roll_islanding_day_if_needed()
        seconds = self._islanding_seconds_today
        if self._islanding_started_at is not None:
            seconds += (
                datetime.now(timezone.utc) - self._islanding_started_at
            ).total_seconds()
        return seconds / 3600.0

    def _record_islanding_ended(self) -> None:
        """Fold an in-progress islanding session's elapsed time into today's
        total. Safe to call even if we weren't islanded (a no-op then) -
        async_allow_export calls this unconditionally rather than tracking
        whether the previous curtailment was 'soft' or 'strong' itself.

        Order matters: elapsed time is computed and _islanding_started_at
        cleared *before* the day-roll check, since that check deliberately
        no-ops while a session looks active (see _roll_islanding_day_if_needed)
        - clearing first is what lets a session that happened to span
        midnight actually roll over once it ends, landing its whole
        duration against the day it ended on.
        """
        if self._islanding_started_at is None:
            return
        elapsed = (datetime.now(timezone.utc) - self._islanding_started_at).total_seconds()
        self._islanding_started_at = None
        self._roll_islanding_day_if_needed()
        self._islanding_seconds_today += max(elapsed, 0.0)

    def _roll_islanding_day_if_needed(self) -> None:
        """Reset the daily counter on a UTC calendar-day boundary - but never
        while a session is actively in progress (_islanding_started_at set),
        so a session spanning midnight can't have the counter reset out from
        under it mid-flight (which would let a fresh 24h-cap habitually
        restart the exact moment the old one was hit). The whole session's
        duration instead lands against the day it ended on, once
        _record_islanding_ended runs - a deliberate simplification, not
        exact per-calendar-day accounting.
        """
        if self._islanding_started_at is not None:
            return
        today = datetime.now(timezone.utc).date()
        if self._islanding_day != today:
            self._islanding_day = today
            self._islanding_seconds_today = 0.0

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

        # Neither backend raises when the underlying transport rejects a
        # write — both log an error and return a falsy result instead, which
        # would otherwise look identical to success. Treat a falsy result as
        # failure.
        if not result:
            if self._is_v1r:
                # Already on the v1r connection (powerwall_v1r.py) - a falsy
                # result here means the write itself was rejected, not that
                # v1r is unavailable. Most common cause: the RSA key is
                # registered but not yet VERIFIED (toggle a breaker).
                raise PowerwallError(
                    f"{method_name}() returned no result over the v1r "
                    "connection. If the key was just registered, it may still "
                    "be PENDING_VERIFICATION — toggle a Powerwall breaker "
                    "OFF then back ON to trigger verification."
                )
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
