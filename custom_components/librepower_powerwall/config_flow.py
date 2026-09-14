# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 LibrePower contributors
# Full license: /LICENSE. Third-party exception (this file is NOT it): /NOTICE.

"""Config flow: pick a core instance, then connect the Powerwall.

Order matters the other way round from how core used to do it: we need to
know *which* LibrePower core instance to attach to before doing anything
else, since that decides where read_only/control_enabled comes from.

Two ways to connect, chosen on the "connection_method" step:
  - password: the original flow - gateway password, tests over gw_pwd/
    pypowerwall (async_step_powerwall).
  - pair_first: pairs via Tesla's Owner API *before* ever touching the local
    network (pairing.py - cloud + a physical breaker toggle, no password),
    then tests connectivity over pure v1r (async_step_powerwall_v1r,
    powerwall_v1r.py). Never needs the sticker password.

The pairing steps themselves (login, site pick, register, toggle-confirm)
are shared with the post-setup options flow via PairingStepsMixin below,
rather than duplicated - the only thing that differs between "pairing during
initial setup" and "pairing after the fact" is what happens once a key is
VERIFIED, which each flow implements as _async_finish_pairing().
"""
from __future__ import annotations

import logging
import os
import tempfile
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
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
    PowerwallAuthError,
    PowerwallClient,
    PowerwallError,
    PowerwallUnreachableError,
)

_LOGGER = logging.getLogger(__name__)

CONNECTION_METHOD_PASSWORD = "password"
CONNECTION_METHOD_PAIR_FIRST = "pair_first"


class PairingStepsMixin:
    """Tesla v1r pairing steps (login, site pick, register, toggle-confirm),
    shared between the initial config flow's pair-first path and the
    post-setup options flow's pairing step. See pairing.py's module
    docstring for the protocol itself.

    A subclass must call ``_init_pairing_state()`` from its own ``__init__``
    (plain attribute init, not a cooperative ``super().__init__()`` chain -
    simpler to reason about with the multiple inheritance this mixin implies)
    and implement ``_async_finish_pairing()``, called once a key reaches
    VERIFIED - what happens next is the one thing that actually differs
    between "pairing during initial setup" (move on to the next setup step)
    and "pairing after the fact" (persist into the existing entry and close).
    """

    hass: Any  # provided by ConfigFlow/OptionsFlow

    def _init_pairing_state(self) -> None:
        self._challenge: pairing.PkceChallenge | None = None
        self._keypair: pairing.RsaKeypair | None = None
        self._access_token: str | None = None
        self._sites: list[pairing.EnergySite] = []
        self._site: pairing.EnergySite | None = None

    async def _async_finish_pairing(self) -> ConfigFlowResult:
        raise NotImplementedError

    # -- step: Tesla login (PKCE, Owner API) -------------------------------

    async def async_step_pair_login(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is None:
            # First time in: generate the signing key and a login URL once.
            # Re-entries after a validation error reuse both rather than
            # generating fresh ones on every failed paste.
            if self._challenge is None:
                self._keypair = await self.hass.async_add_executor_job(
                    pairing.generate_rsa_keypair
                )
                self._challenge = pairing.build_pkce_challenge()
            return self._pair_login_form()

        assert self._challenge is not None and self._keypair is not None
        try:
            code = pairing.parse_authorization_code(
                user_input["redirect_url"], self._challenge.state
            )
            self._access_token = await pairing.async_exchange_code(
                code, self._challenge.verifier
            )
            self._sites = await pairing.async_get_energy_sites(self._access_token)
        except pairing.PairingAuthError:
            return self._pair_login_form(errors={"base": "pairing_auth_error"})
        except pairing.PairingSiteNotFoundError:
            return self._pair_login_form(errors={"base": "pairing_no_site"})
        except pairing.PairingError:
            _LOGGER.exception("Tesla pairing login failed")
            return self._pair_login_form(errors={"base": "pairing_error"})

        if len(self._sites) > 1:
            return await self.async_step_pair_site()
        self._site = self._sites[0]
        return await self._async_register_and_continue()

    def _pair_login_form(self, errors: dict[str, str] | None = None) -> ConfigFlowResult:
        assert self._challenge is not None
        return self.async_show_form(
            step_id="pair_login",
            data_schema=vol.Schema({vol.Required("redirect_url"): str}),
            description_placeholders={
                "authorize_url": pairing.build_authorize_url(self._challenge)
            },
            errors=errors or {},
        )

    # -- step: pick a site, only shown for multi-site Tesla accounts ------

    async def async_step_pair_site(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            site_id = user_input["site_id"]
            self._site = next(s for s in self._sites if s.site_id == site_id)
            return await self._async_register_and_continue()

        return self.async_show_form(
            step_id="pair_site",
            data_schema=vol.Schema(
                {
                    vol.Required("site_id"): vol.In(
                        {site.site_id: site.name for site in self._sites}
                    )
                }
            ),
        )

    # -- registration + physical-toggle confirmation -----------------------

    async def _async_register_and_continue(self) -> ConfigFlowResult:
        assert self._access_token is not None
        assert self._site is not None
        assert self._keypair is not None
        try:
            state = await pairing.async_register_key(
                self._access_token, self._site, self._keypair
            )
        except pairing.PairingError:
            _LOGGER.exception("Tesla key registration failed")
            return self._pair_login_form(errors={"base": "pairing_error"})

        if state == pairing.STATE_VERIFIED:
            return await self.async_step_pair_success()
        return await self.async_step_pair_toggle()

    async def async_step_pair_toggle(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Ask the user to physically toggle the DC isolator, then check.

        One check per submission, not a blocking poll loop - re-submitting
        this form (the frontend just shows it as a button) re-checks without
        ever tying up a request for longer than one HTTP call, and the user
        can back out of the flow at any point instead of being stuck behind
        a fixed sleep.
        """
        errors: dict[str, str] = {}

        if user_input is not None:
            assert self._access_token is not None
            assert self._site is not None
            assert self._keypair is not None
            try:
                state = await pairing.async_poll_key_state(
                    self._access_token, self._site, self._keypair
                )
            except pairing.PairingError:
                _LOGGER.exception("Tesla key verification check failed")
                errors["base"] = "pairing_error"
            else:
                if state == pairing.STATE_VERIFIED:
                    return await self.async_step_pair_success()
                errors["base"] = "pairing_still_pending"

        return self.async_show_form(
            step_id="pair_toggle",
            data_schema=vol.Schema({}),
            errors=errors,
        )

    async def async_step_pair_success(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        assert self._keypair is not None
        assert self._site is not None

        if user_input is not None:
            return await self._async_finish_pairing()

        return self.async_show_form(
            step_id="pair_success",
            data_schema=vol.Schema({}),
            description_placeholders={
                "site_name": self._site.name,
                "din": self._site.din,
                "fingerprint": self._keypair.fingerprint_sha256,
            },
        )


class LibrePowerPowerwallConfigFlow(PairingStepsMixin, ConfigFlow, domain=DOMAIN):
    """Guided setup: which core instance, then the Powerwall connection."""

    VERSION = 1

    def __init__(self) -> None:
        self._data: dict[str, Any] = {}
        self._reauth_entry: ConfigEntry | None = None
        self._init_pairing_state()

    @staticmethod
    @callback
    def async_get_options_flow(entry: ConfigEntry) -> "LibrePowerPowerwallOptionsFlow":
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

    # -- step 2: password, or pair first? --------------------------------------

    async def async_step_connection_method(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            if user_input["connection_method"] == CONNECTION_METHOD_PAIR_FIRST:
                return await self.async_step_pair_login()
            return await self.async_step_powerwall()

        return self.async_show_form(
            step_id="connection_method",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        "connection_method", default=CONNECTION_METHOD_PASSWORD
                    ): vol.In(
                        {
                            CONNECTION_METHOD_PASSWORD: "I have the gateway password (printed on the Powerwall)",
                            CONNECTION_METHOD_PAIR_FIRST: "Pair with my Tesla account instead (no password, PW3 wired LAN only)",
                        }
                    )
                }
            ),
        )

    # -- step 3a: connect the Powerwall (gateway password) ---------------------

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

    # -- step 3b: connect the Powerwall (pure v1r, no password) ---------------

    async def _async_finish_pairing(self) -> ConfigFlowResult:
        assert self._keypair is not None
        assert self._site is not None
        self._data[CONF_RSA_PRIVATE_KEY_PEM] = self._keypair.private_key_pem
        self._data[CONF_GATEWAY_DIN] = self._site.din
        return await self.async_step_powerwall_v1r()

    async def async_step_powerwall_v1r(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Same shape as async_step_powerwall, minus the password field -
        pairing already happened (async_step_pair_login et al, via the
        mixin), so this only needs host + hardware specs, and tests
        connectivity over pure v1r (powerwall_v1r.py) instead of gw_pwd.
        """
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

            # The config entry doesn't exist yet, so __init__.py's
            # entry-keyed key file (where this same PEM ends up permanently
            # once the entry IS created) isn't available - a temp file gets
            # this one connectivity test through, then is removed either way.
            tmp_key_path = await self.hass.async_add_executor_job(
                _write_temp_key_file, self._data[CONF_RSA_PRIVATE_KEY_PEM]
            )
            try:
                client = PowerwallClient(
                    self.hass,
                    host=user_input[CONF_GATEWAY_HOST],
                    gateway_password="",
                    capacity_wh=user_input[CONF_BATTERY_CAPACITY_WH],
                    max_charge_w=user_input[CONF_MAX_CHARGE_W],
                    max_discharge_w=user_input[CONF_MAX_DISCHARGE_W],
                    charge_efficiency=user_input[CONF_CHARGE_EFFICIENCY],
                    discharge_efficiency=user_input[CONF_DISCHARGE_EFFICIENCY],
                    read_only=not control_enabled,
                    rsa_key_path=tmp_key_path,
                    din=self._data[CONF_GATEWAY_DIN],
                )
                try:
                    await client.async_connect()
                except PowerwallUnreachableError:
                    errors["base"] = "gateway_unreachable"
                except PowerwallError as err:
                    _LOGGER.error("Powerwall v1r setup failed: %s", err)
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
            finally:
                await self.hass.async_add_executor_job(
                    _remove_temp_key_file, tmp_key_path
                )

        return self.async_show_form(
            step_id="powerwall_v1r",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_GATEWAY_HOST): str,
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
    #
    # Password-mode entries only - a v1r-only entry has no password to
    # reject in the first place. If a paired key is ever revoked/unverified
    # by Tesla, that currently just surfaces as write failures (see
    # powerwall.py's _call_write), not a reauth flow of its own - a known
    # gap, not handled here.

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


class LibrePowerPowerwallOptionsFlow(PairingStepsMixin, OptionsFlow):
    """Post-setup: pair for battery control (v1r RSA key registration).

    See pairing.py's module docstring for the full protocol. The paired key
    (and, once powerwall_v1r.py is in play, the DIN needed to drop the
    gateway password entirely) is connection material, not a policy toggle,
    so on success it's written straight into entry.data (same as the gateway
    password itself) rather than entry.options - __init__.py's update
    listener picks up the change and reloads so it takes effect immediately.

    Transient pairing state (the in-progress keypair/tokens/site choice)
    lives only on this flow instance - if the user backs out or the flow
    instance is discarded, nothing partial is ever persisted.
    """

    def __init__(self) -> None:
        self._init_pairing_state()

    # -- entry point ------------------------------------------------------

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        if user_input is not None:
            if user_input["start_pairing"]:
                return await self.async_step_pair_login()
            return self.async_create_entry(title="", data={})

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({vol.Required("start_pairing", default=False): bool}),
            description_placeholders={
                "status": (
                    "Already paired - control writes are enabled (re-pairing "
                    "registers a new key alongside the existing one)."
                    if self.config_entry.data.get(CONF_GATEWAY_DIN)
                    else "Not yet paired - control writes will raise an error "
                    "until this is done."
                )
            },
        )

    async def _async_finish_pairing(self) -> ConfigFlowResult:
        assert self._keypair is not None
        assert self._site is not None
        self.hass.config_entries.async_update_entry(
            self.config_entry,
            data={
                **self.config_entry.data,
                CONF_RSA_PRIVATE_KEY_PEM: self._keypair.private_key_pem,
                CONF_GATEWAY_DIN: self._site.din,
            },
        )
        return self.async_create_entry(title="", data={})


# -- shared helpers -----------------------------------------------------------


def _write_temp_key_file(pem: str) -> str:
    """Blocking. A short-lived key file for the initial pair-first setup's
    one connectivity test - see async_step_powerwall_v1r. Always cleaned up
    by _remove_temp_key_file in the same step's `finally`, success or not.
    """
    fd, path = tempfile.mkstemp(suffix=".pem", prefix="librepower_powerwall_setup_")
    with os.fdopen(fd, "w") as f:
        f.write(pem)
    os.chmod(path, 0o600)
    return path


def _remove_temp_key_file(path: str) -> None:
    """Blocking."""
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
