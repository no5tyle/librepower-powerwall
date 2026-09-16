# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 LibrePower contributors
# Full license: /LICENSE. Third-party exception (this file is NOT it): /NOTICE.

"""Config flow: pick a core instance, then connect the Powerwall.

Order matters the other way round from how core used to do it: we need to
know *which* LibrePower core instance to attach to before doing anything
else, since that decides where read_only/control_enabled comes from.

Two ways to connect the Powerwall
----------------------------------
**Gateway password** (unchanged, always available): the original path -
type the password printed on the Gateway. Works everywhere pypowerwall's
TEDAPI reaches, but as of some PW3 + Backup Gateway 2 firmware (confirmed
26.x) local TEDAPI login is rejected outright regardless of password
correctness - see https://github.com/jasonacox/pypowerwall/issues/284 - not
something fixable from here.

**Pair via Teslemetry** (new, only offered if a loaded `teslemetry` config
entry with a battery-capable energy site exists): no local password at all,
at any step. This flow briefly offered a "pair with my Tesla account"
path built on pairing.py's own Owner API login - that broke when Tesla
decommissioned owner-api.teslamotors.com for third-party callers in June
2026. Reviving our own OAuth app needs a registered Tesla developer/business
account, a hosted `.well-known` public key, and ongoing custody of every
user's refresh token - real infrastructure this project isn't set up to run.
Rewritten instead to bootstrap the same RSA-pairing protocol through an
*existing* Teslemetry config entry (a service that already holds a
registered, Tesla-approved Fleet API app) - see pairing.py's own docstring
for the full design.

Deliberately import-free w.r.t. Teslemetry/tesla_fleet_api: every call
into a Teslemetry site's API object below is duck-typed (plain attribute/
method access on an object obtained at runtime), never a module-level
import - `tesla_fleet_api` is only installed in the Home Assistant venv
once a user has actually set up Teslemetry, so a hard import here would
break this entire integration's loading for the (currently most) users who
haven't. The cost is the usual cross-integration-without-a-stable-API
fragility (see battery.py's own docstring for the same honest caveat about
core/adapter coupling) - if Teslemetry ever renames `runtime_data.
energysites` or `.api`, this breaks silently rather than at import time.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigEntryState,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.core import callback

from custom_components.librepower.const import (
    CONF_CONTROL_ENABLED,
    DEFAULT_CONTROL_ENABLED,
)

from . import pairing
from .const import (
    CONF_BATTERY_CAPACITY_WH,
    CONF_CHARGE_EFFICIENCY,
    CONF_CORE_ENTRY_ID,
    CONF_DISCHARGE_EFFICIENCY,
    CONF_GATEWAY_DIN,
    CONF_GATEWAY_HOST,
    CONF_GATEWAY_PASSWORD,
    CONF_MAX_CHARGE_W,
    CONF_MAX_DISCHARGE_W,
    CONF_MAX_ISLANDING_HOURS_PER_DAY,
    CONF_MIN_SOC_FOR_ISLANDING,
    CONF_RSA_PRIVATE_KEY_PEM,
    CORE_DOMAIN,
    DEFAULT_BATTERY_CAPACITY_WH,
    DEFAULT_CHARGE_EFFICIENCY,
    DEFAULT_DISCHARGE_EFFICIENCY,
    DEFAULT_GATEWAY_HOST,
    DEFAULT_MAX_CHARGE_W,
    DEFAULT_MAX_DISCHARGE_W,
    DOMAIN,
)
from .powerwall import (
    DEFAULT_MAX_ISLANDING_HOURS_PER_DAY,
    DEFAULT_MIN_SOC_FOR_ISLANDING,
    PowerwallAuthError,
    PowerwallClient,
    PowerwallError,
    PowerwallUnreachableError,
)

_LOGGER = logging.getLogger(__name__)

# The Gateway only honours a freshly-registered key's physical breaker
# toggle for ~2 minutes (per hass-powerwall-v1r's own comment on the same
# protocol) - this bounded poll window matches that, checked every 5s so a
# quick toggle doesn't sit waiting for the full interval.
_PAIR_POLL_ATTEMPTS = 24
_PAIR_POLL_INTERVAL_SECONDS = 5


def _extract_host(networking_status: dict[str, Any] | None) -> str:
    """Best-effort LAN IPv4 from a get_networking_status() payload.

    Checks ``eth`` then ``wifi``, preferring an interface flagged
    ``active_route``, then any interface with an address at all. Returns ""
    (not an error) on anything unexpected - host entry always has a manual
    fallback field, this is purely a convenience.
    """
    if not networking_status:
        return ""
    payload = networking_status.get("response", networking_status)
    if not isinstance(payload, dict):
        return ""

    def _addr(iface: Any) -> str:
        if not isinstance(iface, dict):
            return ""
        ipv4 = iface.get("ipv4_config")
        addr = ipv4.get("address") if isinstance(ipv4, dict) else None
        return addr if isinstance(addr, str) else ""

    interfaces = [payload.get(name) for name in ("eth", "wifi")]
    for iface in interfaces:
        if isinstance(iface, dict) and iface.get("active_route") and (addr := _addr(iface)):
            return addr
    for iface in interfaces:
        if addr := _addr(iface):
            return addr
    return ""


def _remove_if_exists(path: str) -> None:
    """Best-effort cleanup of the temporary pairing-verify key file."""
    if os.path.exists(path):
        os.remove(path)


class LibrePowerPowerwallConfigFlow(ConfigFlow, domain=DOMAIN):
    """Guided setup: which core instance, then the Powerwall connection."""

    VERSION = 1

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._reauth_entry: ConfigEntry | None = None
        # -- Teslemetry pairing state, populated as async_step_pair_teslemetry
        # / async_step_pair_confirm progress -------------------------------
        self._pair_entry: ConfigEntry | None = None
        self._pair_site: Any = None
        self._pair_site_name: str = ""
        self._pair_keypair: pairing.RsaKeypair | None = None
        self._pair_din: str | None = None
        self._pair_host: str = ""

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> "LibrePowerPowerwallOptionsFlow":
        return LibrePowerPowerwallOptionsFlow()

    # -- step 1: which core instance ------------------------------------------

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        core_entries = self.hass.config_entries.async_entries(CORE_DOMAIN)
        if not core_entries:
            return self.async_abort(reason="core_not_configured")

        if len(core_entries) == 1:
            # Don't make the user pick from a list of one.
            self._data[CONF_CORE_ENTRY_ID] = core_entries[0].entry_id
            return await self.async_step_connection_method()

        if user_input is not None:
            self._data[CONF_CORE_ENTRY_ID] = user_input[CONF_CORE_ENTRY_ID]
            return await self.async_step_connection_method()

        choices = {entry.entry_id: entry.title for entry in core_entries}
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {vol.Required(CONF_CORE_ENTRY_ID): vol.In(choices)}
            ),
        )

    # -- step 1.5: gateway password, or pair via an existing Teslemetry entry -

    def _loaded_teslemetry_sites(self) -> list[tuple[ConfigEntry, Any]]:
        """(entry, site) for every loaded Teslemetry energy site that can
        take local control (has a battery) - across every loaded Teslemetry
        config entry, since a user could have more than one. Duck-typed
        throughout - see module docstring for why this never imports
        anything Teslemetry-specific. Empty (not an exception) if the
        `teslemetry` domain has no loaded entries at all.
        """
        entries = [
            e
            for e in self.hass.config_entries.async_entries("teslemetry")
            if e.state is ConfigEntryState.LOADED
        ]
        pairs: list[tuple[ConfigEntry, Any]] = []
        for entry in entries:
            energysites = getattr(getattr(entry, "runtime_data", None), "energysites", None) or []
            for site in energysites:
                # can_local_control defaults True if the attribute is ever
                # missing (an older/newer Teslemetry shape) - offering a
                # site that turns out not to support it just fails the
                # pairing step later with a clear error, safer than hiding
                # every site because one field wasn't where expected.
                if getattr(site, "can_local_control", True):
                    pairs.append((entry, site))
        return pairs

    async def async_step_connection_method(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Offer Teslemetry pairing only when it's actually usable."""
        if not self._loaded_teslemetry_sites():
            return await self.async_step_powerwall()

        if user_input is not None:
            if user_input["method"] == "teslemetry":
                return await self.async_step_pair_teslemetry()
            return await self.async_step_powerwall()

        return self.async_show_form(
            step_id="connection_method",
            data_schema=vol.Schema(
                {
                    vol.Required("method", default="teslemetry"): vol.In(
                        {
                            "teslemetry": "Pair via Teslemetry (no Gateway password needed)",
                            "gateway_password": "Gateway password",
                        }
                    )
                }
            ),
        )

    # -- step 2: connect the Powerwall ----------------------------------------

    async def async_step_powerwall(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            core_entry = self.hass.config_entries.async_get_entry(
                self._data[CONF_CORE_ENTRY_ID]
            )
            control_enabled = (
                core_entry.options.get(CONF_CONTROL_ENABLED, DEFAULT_CONTROL_ENABLED)
                if core_entry
                else DEFAULT_CONTROL_ENABLED
            )

            client = PowerwallClient(
                self.hass,
                host=user_input[CONF_GATEWAY_HOST],
                gateway_password=user_input[CONF_GATEWAY_PASSWORD],
                capacity_wh=user_input[CONF_BATTERY_CAPACITY_WH],
                max_charge_w=user_input[CONF_MAX_CHARGE_W],
                max_discharge_w=user_input[CONF_MAX_DISCHARGE_W],
                charge_efficiency=user_input[CONF_CHARGE_EFFICIENCY],
                discharge_efficiency=user_input[CONF_DISCHARGE_EFFICIENCY],
                read_only=not control_enabled,
            )
            try:
                await client.async_connect()
            except PowerwallAuthError:
                errors["base"] = "invalid_gateway_password"
            except PowerwallUnreachableError:
                errors["base"] = "gateway_unreachable"
            except PowerwallError as err:
                _LOGGER.error("Powerwall setup failed: %s", err)
                errors["base"] = "unknown"
            else:
                await client.async_close()
                await self.async_set_unique_id(
                    f"{self._data[CONF_CORE_ENTRY_ID]}_{user_input[CONF_GATEWAY_HOST]}"
                )
                self._abort_if_unique_id_configured()
                self._data.update(user_input)
                return self.async_create_entry(
                    title="Powerwall", data=self._data
                )

        return self.async_show_form(
            step_id="powerwall",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_GATEWAY_HOST, default=DEFAULT_GATEWAY_HOST): str,
                    vol.Required(CONF_GATEWAY_PASSWORD): str,
                    vol.Required(
                        CONF_BATTERY_CAPACITY_WH, default=DEFAULT_BATTERY_CAPACITY_WH
                    ): vol.Coerce(float),
                    vol.Required(
                        CONF_MAX_CHARGE_W, default=DEFAULT_MAX_CHARGE_W
                    ): vol.Coerce(float),
                    vol.Required(
                        CONF_MAX_DISCHARGE_W, default=DEFAULT_MAX_DISCHARGE_W
                    ): vol.Coerce(float),
                    vol.Optional(
                        CONF_CHARGE_EFFICIENCY, default=DEFAULT_CHARGE_EFFICIENCY
                    ): vol.All(vol.Coerce(float), vol.Range(min=0.0, max=1.0)),
                    vol.Optional(
                        CONF_DISCHARGE_EFFICIENCY, default=DEFAULT_DISCHARGE_EFFICIENCY
                    ): vol.All(vol.Coerce(float), vol.Range(min=0.0, max=1.0)),
                }
            ),
            errors=errors,
        )

    # -- Teslemetry-bootstrapped pairing (no Gateway password) ----------------

    def _control_enabled_for_core(self) -> bool:
        core_entry = self.hass.config_entries.async_get_entry(
            self._data[CONF_CORE_ENTRY_ID]
        )
        return (
            core_entry.options.get(CONF_CONTROL_ENABLED, DEFAULT_CONTROL_ENABLED)
            if core_entry
            else DEFAULT_CONTROL_ENABLED
        )

    async def async_step_pair_teslemetry(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Pick which Teslemetry energy site to pair, if there's more than one."""
        sites = self._loaded_teslemetry_sites()
        if not sites:
            # Raced with something unloading Teslemetry between the previous
            # step and this one - fall back rather than get stuck.
            return await self.async_step_powerwall()

        if len(sites) == 1:
            entry, site = sites[0]
            return await self._start_pairing(entry, site)

        if user_input is not None:
            chosen_id = user_input["site"]
            for entry, site in sites:
                if f"{entry.entry_id}:{getattr(site, 'id', '')}" == chosen_id:
                    return await self._start_pairing(entry, site)
            return await self.async_step_pair_teslemetry()

        choices = {
            f"{entry.entry_id}:{getattr(site, 'id', '')}": self._site_label(entry, site)
            for entry, site in sites
        }
        return self.async_show_form(
            step_id="pair_teslemetry",
            data_schema=vol.Schema({vol.Required("site"): vol.In(choices)}),
        )

    @staticmethod
    def _site_label(entry: ConfigEntry, site: Any) -> str:
        device = getattr(site, "device", None)
        name = device.get("name") if isinstance(device, dict) else None
        return name or f"{entry.title} - site {getattr(site, 'id', '?')}"

    async def _start_pairing(self, entry: ConfigEntry, site: Any) -> ConfigFlowResult:
        """Generate/reuse a keypair, register it if not already, and move
        to the breaker-toggle confirmation step - or straight past it if
        this exact key is already VERIFIED (a resumed/retried flow).
        """
        self._pair_entry = entry
        self._pair_site = site
        self._pair_site_name = self._site_label(entry, site)

        if self._pair_keypair is None:
            self._pair_keypair = await self.hass.async_add_executor_job(
                pairing.generate_rsa_keypair
            )

        site_api = getattr(site, "api", None)
        if site_api is None:
            return self.async_abort(reason="teslemetry_site_unavailable")

        try:
            state = await pairing.async_poll_key_state(site_api, self._pair_keypair)
        except Exception as err:  # noqa: BLE001 - tesla_fleet_api's own hierarchy, kept import-free (see module docstring)
            _LOGGER.warning("Checking existing pairing state failed: %s", err)
            state = None

        if state == pairing.STATE_VERIFIED:
            return await self._finish_verified_pairing()

        # Either no registration exists yet, or one does but isn't VERIFIED
        # (state check above failed to find it, or it's still PENDING).
        # Re-registering either way is safe and, per the Gateway's ~2-minute
        # confirmation window, necessary on a retry - an old PENDING
        # registration whose window already lapsed needs a fresh one before
        # prompting the user to toggle the breaker again.
        try:
            await pairing.async_register_key(site_api, self._pair_keypair)
        except Exception as err:  # noqa: BLE001
            _LOGGER.error("Registering the pairing key with Teslemetry failed: %s", err)
            return self.async_abort(reason="pair_register_failed")

        return await self.async_step_pair_confirm()

    async def async_step_pair_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Prompt for the physical breaker toggle, then poll for VERIFIED."""
        assert self._pair_keypair is not None and self._pair_site is not None

        if user_input is None:
            return self.async_show_form(
                step_id="pair_confirm",
                data_schema=vol.Schema({}),
                description_placeholders={"site_name": self._pair_site_name},
            )

        site_api = getattr(self._pair_site, "api", None)
        for _ in range(_PAIR_POLL_ATTEMPTS):
            try:
                state = await pairing.async_poll_key_state(site_api, self._pair_keypair)
            except Exception as err:  # noqa: BLE001
                _LOGGER.debug("Pairing poll attempt failed, retrying: %s", err)
                state = None
            if state == pairing.STATE_VERIFIED:
                return await self._finish_verified_pairing()
            await asyncio.sleep(_PAIR_POLL_INTERVAL_SECONDS)

        return self.async_show_form(
            step_id="pair_confirm",
            data_schema=vol.Schema({}),
            errors={"base": "pair_pending"},
            description_placeholders={"site_name": self._pair_site_name},
        )

    async def _finish_verified_pairing(self) -> ConfigFlowResult:
        """Key is VERIFIED - look up the DIN and a best-effort host, then
        move to the shared battery-specs/local-verify step.
        """
        assert self._pair_keypair is not None
        site_api = getattr(self._pair_site, "api", None)

        try:
            din = await pairing.async_get_din(site_api)
        except Exception as err:  # noqa: BLE001
            _LOGGER.error("Reading the Gateway DIN via Teslemetry failed: %s", err)
            return self.async_abort(reason="pair_din_failed")
        if not din:
            return self.async_abort(reason="pair_din_failed")
        self._pair_din = din

        try:
            networking = await site_api.get_networking_status()
        except Exception as err:  # noqa: BLE001
            _LOGGER.debug("Networking status unavailable, host entry will be manual: %s", err)
            networking = None
        self._pair_host = _extract_host(networking)

        return await self.async_step_pairing_battery_specs()

    async def async_step_pairing_battery_specs(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Battery specs + a real local connectivity check - the same
        information async_step_powerwall collects, just without a password
        field, since v1r needs none (see pairing.py's module docstring).
        """
        assert self._pair_keypair is not None and self._pair_din is not None
        errors: dict[str, str] = {}

        if user_input is not None:
            host = user_input[CONF_GATEWAY_HOST]
            key_path = self.hass.config.path(DOMAIN, f"pairing_verify_{self.flow_id}.pem")

            def _write_temp_key() -> None:
                os.makedirs(os.path.dirname(key_path), exist_ok=True)
                fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w") as f:
                    f.write(self._pair_keypair.private_key_pem)

            await self.hass.async_add_executor_job(_write_temp_key)
            try:
                client = PowerwallClient(
                    self.hass,
                    host=host,
                    gateway_password="",
                    capacity_wh=user_input[CONF_BATTERY_CAPACITY_WH],
                    max_charge_w=user_input[CONF_MAX_CHARGE_W],
                    max_discharge_w=user_input[CONF_MAX_DISCHARGE_W],
                    charge_efficiency=user_input[CONF_CHARGE_EFFICIENCY],
                    discharge_efficiency=user_input[CONF_DISCHARGE_EFFICIENCY],
                    read_only=not self._control_enabled_for_core(),
                    rsa_key_path=key_path,
                    din=self._pair_din,
                )
                try:
                    await client.async_connect()
                except PowerwallUnreachableError:
                    errors["base"] = "gateway_unreachable"
                except PowerwallError as err:
                    _LOGGER.error("Local v1r verify failed: %s", err)
                    errors["base"] = "unknown"
                else:
                    await client.async_close()
                    await self.async_set_unique_id(
                        f"{self._data[CONF_CORE_ENTRY_ID]}_{host}"
                    )
                    self._abort_if_unique_id_configured()
                    self._data.update(
                        {
                            CONF_GATEWAY_HOST: host,
                            CONF_BATTERY_CAPACITY_WH: user_input[CONF_BATTERY_CAPACITY_WH],
                            CONF_MAX_CHARGE_W: user_input[CONF_MAX_CHARGE_W],
                            CONF_MAX_DISCHARGE_W: user_input[CONF_MAX_DISCHARGE_W],
                            CONF_CHARGE_EFFICIENCY: user_input[CONF_CHARGE_EFFICIENCY],
                            CONF_DISCHARGE_EFFICIENCY: user_input[CONF_DISCHARGE_EFFICIENCY],
                            CONF_RSA_PRIVATE_KEY_PEM: self._pair_keypair.private_key_pem,
                            CONF_GATEWAY_DIN: self._pair_din,
                        }
                    )
                    return self.async_create_entry(
                        title=self._pair_site_name or "Powerwall", data=self._data
                    )
            finally:
                # __init__.py's _async_ensure_rsa_key_file writes the real,
                # per-entry-id key file on actual setup - this one only ever
                # existed for this connectivity check.
                await self.hass.async_add_executor_job(_remove_if_exists, key_path)

        return self.async_show_form(
            step_id="pairing_battery_specs",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_GATEWAY_HOST, default=self._pair_host): str,
                    vol.Required(
                        CONF_BATTERY_CAPACITY_WH, default=DEFAULT_BATTERY_CAPACITY_WH
                    ): vol.Coerce(float),
                    vol.Required(
                        CONF_MAX_CHARGE_W, default=DEFAULT_MAX_CHARGE_W
                    ): vol.Coerce(float),
                    vol.Required(
                        CONF_MAX_DISCHARGE_W, default=DEFAULT_MAX_DISCHARGE_W
                    ): vol.Coerce(float),
                    vol.Optional(
                        CONF_CHARGE_EFFICIENCY, default=DEFAULT_CHARGE_EFFICIENCY
                    ): vol.All(vol.Coerce(float), vol.Range(min=0.0, max=1.0)),
                    vol.Optional(
                        CONF_DISCHARGE_EFFICIENCY, default=DEFAULT_DISCHARGE_EFFICIENCY
                    ): vol.All(vol.Coerce(float), vol.Range(min=0.0, max=1.0)),
                }
            ),
            errors=errors,
        )

    # -- reauth: gateway password ---------------------------------------------

    async def async_step_reauth(
        self, entry_data: dict[str, Any]
    ) -> ConfigFlowResult:
        """Triggered when the Gateway starts rejecting our password."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        entry = self._reauth_entry
        assert entry is not None

        if user_input is not None:
            client = PowerwallClient(
                self.hass,
                host=entry.data[CONF_GATEWAY_HOST],
                gateway_password=user_input[CONF_GATEWAY_PASSWORD],
                capacity_wh=entry.data[CONF_BATTERY_CAPACITY_WH],
                max_charge_w=entry.data[CONF_MAX_CHARGE_W],
                max_discharge_w=entry.data[CONF_MAX_DISCHARGE_W],
                charge_efficiency=entry.data.get(
                    CONF_CHARGE_EFFICIENCY, DEFAULT_CHARGE_EFFICIENCY
                ),
                discharge_efficiency=entry.data.get(
                    CONF_DISCHARGE_EFFICIENCY, DEFAULT_DISCHARGE_EFFICIENCY
                ),
            )
            try:
                await client.async_connect()
            except PowerwallAuthError:
                errors["base"] = "invalid_gateway_password"
            except PowerwallUnreachableError:
                errors["base"] = "gateway_unreachable"
            except PowerwallError:
                errors["base"] = "unknown"
            else:
                await client.async_close()
                return self.async_update_reload_and_abort(
                    entry, data={**entry.data, **user_input}
                )

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({vol.Required(CONF_GATEWAY_PASSWORD): str}),
            errors=errors,
        )


class LibrePowerPowerwallOptionsFlow(OptionsFlow):
    """Post-setup tuning for the islanding safety gate.

    Everything else about this adapter (Gateway host/password, battery
    specs, efficiency) is set once at initial setup and rarely revisited -
    only the islanding gate's own safety knobs (min_soc_for_islanding,
    max_islanding_hours_per_day - see powerwall.py's
    PowerwallIslandingBlockedError) get an options screen, since those are
    the one part of this adapter callers might reasonably want to retune
    without reconfiguring the whole connection. A single step is enough;
    there's no branching like core's control-handover flow needs.
    """

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(data=user_input)

        current = self.config_entry.options
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_MIN_SOC_FOR_ISLANDING,
                        default=current.get(
                            CONF_MIN_SOC_FOR_ISLANDING, DEFAULT_MIN_SOC_FOR_ISLANDING
                        ),
                    ): vol.All(vol.Coerce(float), vol.Range(min=0.0, max=1.0)),
                    vol.Required(
                        CONF_MAX_ISLANDING_HOURS_PER_DAY,
                        default=current.get(
                            CONF_MAX_ISLANDING_HOURS_PER_DAY,
                            DEFAULT_MAX_ISLANDING_HOURS_PER_DAY,
                        ),
                    ): vol.All(vol.Coerce(float), vol.Range(min=0.0, max=24.0)),
                }
            ),
        )
