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

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady

from custom_components.librepower import async_register_battery

from .const import (
    CONF_BATTERY_CAPACITY_WH,
    CONF_CORE_ENTRY_ID,
    CONF_GATEWAY_HOST,
    CONF_GATEWAY_PASSWORD,
    CONF_MAX_CHARGE_W,
    CONF_MAX_DISCHARGE_W,
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

    client = PowerwallClient(
        hass,
        host=entry.data[CONF_GATEWAY_HOST],
        gateway_password=entry.data[CONF_GATEWAY_PASSWORD],
        capacity_wh=entry.data[CONF_BATTERY_CAPACITY_WH],
        max_charge_w=entry.data[CONF_MAX_CHARGE_W],
        max_discharge_w=entry.data[CONF_MAX_DISCHARGE_W],
        read_only=not control_enabled,
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
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Tear down. Does not unregister from core - see async_register_battery's
    docstring in core for the known gap this leaves.
    """
    client = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if client is not None:
        await client.async_close()
    return True
