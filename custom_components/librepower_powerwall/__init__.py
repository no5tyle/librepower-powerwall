# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 LibrePower contributors
# Full license: /LICENSE. Third-party exception (this file is NOT it): /NOTICE.

"""LibrePower - Powerwall adapter.

Connects to a Tesla Powerwall over local TEDAPI and registers itself with a
running LibrePower core instance. This integration has no coordinator, no
sensors, and no config options of its own beyond initial setup - it is
intentionally thin. All of the actual optimisation, pricing, and scheduling
logic lives in the ``librepower`` core integration this depends on.
"""
from __future__ import annotations

import logging
import os

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady

from custom_components.librepower import async_register_battery

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
    CONF_RSA_PRIVATE_KEY_PEM,
    DEFAULT_CHARGE_EFFICIENCY,
    DEFAULT_DISCHARGE_EFFICIENCY,
    DOMAIN,
)
from .powerwall import PowerwallAuthError, PowerwallClient, PowerwallError

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Connect to the Powerwall and register with core.

    Reads control_enabled from *core's* entry options, not this entry's own -
    there is deliberately no separate shadow-mode toggle here. See
    config_flow.py's async_step_powerwall for where that value is actually
    read at setup time; it isn't re-read on every restart, so changing core's
    control setting after this entry exists requires reloading this entry too
    (not yet automated - a real gap worth fixing before relying on this for
    a live handover).
    """
    from custom_components.librepower.const import (
        CONF_CONTROL_ENABLED,
        DEFAULT_CONTROL_ENABLED,
    )

    core_entry_id = entry.data[CONF_CORE_ENTRY_ID]
    core_entry = hass.config_entries.async_get_entry(core_entry_id)
    control_enabled = (
        core_entry.options.get(CONF_CONTROL_ENABLED, DEFAULT_CONTROL_ENABLED)
        if core_entry
        else DEFAULT_CONTROL_ENABLED
    )

    rsa_key_path = await _async_ensure_rsa_key_file(hass, entry)

    client = PowerwallClient(
        hass,
        host=entry.data[CONF_GATEWAY_HOST],
        # Absent entirely on a password-free (pure-v1r, pair-first) setup -
        # see config_flow.py's async_step_powerwall_v1r. PowerwallClient
        # never reads gateway_password in that mode (powerwall.py's
        # _is_v1r branch), so an empty string here is inert either way.
        gateway_password=entry.data.get(CONF_GATEWAY_PASSWORD, ""),
        capacity_wh=entry.data[CONF_BATTERY_CAPACITY_WH],
        max_charge_w=entry.data[CONF_MAX_CHARGE_W],
        max_discharge_w=entry.data[CONF_MAX_DISCHARGE_W],
        charge_efficiency=entry.data.get(
            CONF_CHARGE_EFFICIENCY, DEFAULT_CHARGE_EFFICIENCY
        ),
        discharge_efficiency=entry.data.get(
            CONF_DISCHARGE_EFFICIENCY, DEFAULT_DISCHARGE_EFFICIENCY
        ),
        read_only=not control_enabled,
        rsa_key_path=rsa_key_path,
        din=entry.data.get(CONF_GATEWAY_DIN),
    )

    try:
        await client.async_connect()
    except PowerwallAuthError as err:
        raise ConfigEntryAuthFailed(str(err)) from err
    except PowerwallError as err:
        raise ConfigEntryNotReady(f"Cannot reach Powerwall: {err}") from err

    try:
        await async_register_battery(hass, core_entry_id, client)
    except KeyError as err:
        # Core entry_id doesn't correspond to a loaded LibrePower instance -
        # core might not have finished starting yet. Retry via HA's normal
        # ConfigEntryNotReady backoff rather than failing permanently.
        await client.async_close()
        raise ConfigEntryNotReady(
            "LibrePower core is not ready to accept a battery yet"
        ) from err

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = client
    # The options flow's pairing step (config_flow.py) writes the v1r key
    # straight into entry.data and relies on this listener to pick it up -
    # without a reload, a newly-paired key wouldn't be used until HA restarts.
    entry.async_on_unload(entry.add_update_listener(_async_reload_entry))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Tear down. Does not unregister from core - see async_register_battery's
    docstring in core for the known gap this leaves.
    """
    client = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if client is not None:
        await client.async_close()
    return True


async def _async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def _async_ensure_rsa_key_file(hass: HomeAssistant, entry: ConfigEntry) -> str | None:
    """Materialise the paired v1r private key (if any) as a file for pypowerwall.

    pypowerwall's ``rsa_key_path`` wants a file path, not raw PEM bytes. The
    PEM itself lives in the config entry (HA encrypts entry data at rest, per
    pairing.py's docstring); this just (re)writes it to disk on every setup
    so the file is never the source of truth a stale copy could drift from.

    Known gap: the file is never deleted on entry removal (only on overwrite
    at next setup) - harmless (it's just an unused key on disk), not yet
    cleaned up in ``async_remove_entry`` because nothing else in this
    integration implements that hook either.
    """
    pem = entry.data.get(CONF_RSA_PRIVATE_KEY_PEM)
    if not pem:
        return None

    key_dir = hass.config.path(DOMAIN)
    key_path = os.path.join(key_dir, f"{entry.entry_id}.pem")

    def _write() -> None:
        os.makedirs(key_dir, exist_ok=True)
        # 0o600 at open time - avoid a chmod-after-write window where the
        # private key is briefly world-readable.
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pem)

    await hass.async_add_executor_job(_write)
    return key_path
