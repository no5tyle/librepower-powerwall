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
from typing import Any

from custom_components.librepower import async_register_battery
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady

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
    DEFAULT_CHARGE_EFFICIENCY,
    DEFAULT_DISCHARGE_EFFICIENCY,
    DOMAIN,
)
from .powerwall import (
    DEFAULT_MAX_ISLANDING_HOURS_PER_DAY,
    DEFAULT_MIN_SOC_FOR_ISLANDING,
    PowerwallAuthError,
    PowerwallClient,
    PowerwallError,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Connect to the Powerwall and register with core.

    Reads control_enabled (and backup_reserve, for the islanding gate's SOC
    floor) from *core's* entry options, not this entry's own - there is
    deliberately no separate shadow-mode toggle here. See
    config_flow.py's async_step_powerwall for where that value is actually
    read at setup time. Live-reloaded: this entry registers an update
    listener on *core's* entry too (below), not just its own, so changing
    either option in core's options flow reloads this entry automatically
    rather than needing a manual reload to pick it up.
    """
    from custom_components.librepower.const import (
        CONF_BACKUP_RESERVE,
        CONF_CONTROL_ENABLED,
        DEFAULT_BACKUP_RESERVE,
        DEFAULT_CONTROL_ENABLED,
    )

    core_entry_id = entry.data[CONF_CORE_ENTRY_ID]
    core_entry = hass.config_entries.async_get_entry(core_entry_id)
    control_enabled = (
        core_entry.options.get(CONF_CONTROL_ENABLED, DEFAULT_CONTROL_ENABLED)
        if core_entry
        else DEFAULT_CONTROL_ENABLED
    )
    # The islanding safety gate's SOC floor (powerwall.py's
    # PowerwallIslandingBlockedError) is never lower than core's own
    # backup_reserve - if the user has already said "never go below X%"
    # for normal operation, intentional grid disconnection (which removes
    # the grid as a backstop entirely) shouldn't be willing to go any
    # lower, only possibly higher than the gate's own sane default.
    #
    # min_soc_for_islanding itself is user-configurable via this entry's
    # own options flow (config_flow.py's LibrePowerPowerwallOptionsFlow) -
    # that configured value (or DEFAULT_MIN_SOC_FOR_ISLANDING if never set)
    # is still max()'d against backup_reserve below, so a user can raise
    # the floor but never accidentally lower it beneath core's own reserve
    # setting.
    backup_reserve = (
        core_entry.options.get(CONF_BACKUP_RESERVE, DEFAULT_BACKUP_RESERVE)
        if core_entry
        else DEFAULT_BACKUP_RESERVE
    )
    configured_min_soc_for_islanding = entry.options.get(
        CONF_MIN_SOC_FOR_ISLANDING, DEFAULT_MIN_SOC_FOR_ISLANDING
    )
    min_soc_for_islanding = max(configured_min_soc_for_islanding, backup_reserve)
    max_islanding_hours_per_day = entry.options.get(
        CONF_MAX_ISLANDING_HOURS_PER_DAY, DEFAULT_MAX_ISLANDING_HOURS_PER_DAY
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
        min_soc_for_islanding=min_soc_for_islanding,
        max_islanding_hours_per_day=max_islanding_hours_per_day,
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
    # ConfigEntry.add_update_listener works on any entry, not just our own -
    # registering on *core's* entry is what makes control_enabled/
    # backup_reserve changes (made in core's options flow, a different
    # integration) reload this entry automatically instead of going stale
    # until a manual reload. Cleaned up via our own entry's async_on_unload,
    # since it's *this* entry's listener slot on core's entry that needs
    # removing when *this* entry unloads - core's own lifecycle is
    # unaffected either way.
    #
    # Deliberately NOT _async_reload_entry here: HA calls an entry's update
    # listeners as listener(hass, that_entry) - registered on core_entry, it
    # would be called with core_entry, and _async_reload_entry would reload
    # *core*, not us. This closure ignores whatever entry the callback
    # reports and always reloads our own, via entry.entry_id captured here.
    if core_entry is not None:

        async def _reload_this_entry(*_args: Any) -> None:
            await hass.config_entries.async_reload(entry.entry_id)

        entry.async_on_unload(core_entry.add_update_listener(_reload_this_entry))
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Tear down, including detaching from core first so its coordinator
    doesn't keep a stale BatteryClient reference once this integration is
    gone - see core's async_register_battery/async_unregister_battery
    docstrings for the detail.
    """
    client = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if client is not None:
        from custom_components.librepower import async_unregister_battery

        await async_unregister_battery(
            hass, entry.data[CONF_CORE_ENTRY_ID], client
        )
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
