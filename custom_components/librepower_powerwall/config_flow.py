# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 LibrePower contributors
# Full license: /LICENSE. Third-party exception (this file is NOT it): /NOTICE.

"""Config flow: pick a core instance, then connect the Powerwall.

Order matters the other way round from how core used to do it: we need to
know *which* LibrePower core instance to attach to before doing anything
else, since that decides where read_only/control_enabled comes from.
"""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult

from custom_components.librepower.const import (
    CONF_CONTROL_ENABLED,
    DEFAULT_CONTROL_ENABLED,
)

from .const import (
    CONF_BATTERY_CAPACITY_WH,
    CONF_CHARGE_EFFICIENCY,
    CONF_CORE_ENTRY_ID,
    CONF_DISCHARGE_EFFICIENCY,
    CONF_GATEWAY_HOST,
    CONF_GATEWAY_PASSWORD,
    CONF_MAX_CHARGE_W,
    CONF_MAX_DISCHARGE_W,
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
    PowerwallAuthError,
    PowerwallClient,
    PowerwallError,
    PowerwallUnreachableError,
)

_LOGGER = logging.getLogger(__name__)


class LibrePowerPowerwallConfigFlow(ConfigFlow, domain=DOMAIN):
    """Guided setup: which core instance, then the Powerwall connection."""

    VERSION = 1

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._reauth_entry: ConfigEntry | None = None

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
            return await self.async_step_powerwall()

        if user_input is not None:
            self._data[CONF_CORE_ENTRY_ID] = user_input[CONF_CORE_ENTRY_ID]
            return await self.async_step_powerwall()

        choices = {entry.entry_id: entry.title for entry in core_entries}
        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {vol.Required(CONF_CORE_ENTRY_ID): vol.In(choices)}
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
