# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 LibrePower contributors
# Full license: /LICENSE. Third-party exception (this file is NOT it): /NOTICE.

"""Constants for the LibrePower Powerwall adapter.

Moved from core's const.py as part of the repo split - these are all
Powerwall-specific and have no business living in a battery-agnostic core.
"""
from __future__ import annotations

DOMAIN = "librepower_powerwall"

# Must match librepower core's own DOMAIN constant - this is how the adapter
# finds core's coordinator via hass.data. Duplicated as a literal rather than
# imported from core's const.py because core's own DOMAIN is unlikely to ever
# change independently, and importing it couples this file to core's const.py
# structure for a single string; the cross-repo import that actually matters
# (the BatteryClient contract) lives in powerwall.py instead.
CORE_DOMAIN = "librepower"

CONF_CORE_ENTRY_ID = "core_entry_id"

CONF_GATEWAY_HOST = "gateway_host"
CONF_GATEWAY_PASSWORD = "gateway_password"
DEFAULT_GATEWAY_HOST = "192.168.91.1"

# v1r pairing (see pairing.py) - present once the user has completed the
# RSA-key registration handshake with Tesla; absent means gateway-password-
# only (telemetry works, every control write raises PowerwallV1rRequiredError).
# Only these two are persisted - the Tesla access/refresh tokens used during
# pairing are deliberately never saved (see pairing.py's module docstring).
CONF_RSA_PRIVATE_KEY_PEM = "rsa_private_key_pem"
CONF_GATEWAY_DIN = "gateway_din"

CONF_BATTERY_CAPACITY_WH = "battery_capacity_wh"
CONF_MAX_CHARGE_W = "max_charge_w"
CONF_MAX_DISCHARGE_W = "max_discharge_w"
DEFAULT_BATTERY_CAPACITY_WH = 13500.0  # One Powerwall
DEFAULT_MAX_CHARGE_W = 5000.0
DEFAULT_MAX_DISCHARGE_W = 5000.0

# Pre-measurement defaults - see custom_components.librepower.battery's
# docstring for why these are provisional, not measured, and reported by
# this adapter rather than assumed by core.
CONF_CHARGE_EFFICIENCY = "charge_efficiency"
CONF_DISCHARGE_EFFICIENCY = "discharge_efficiency"
DEFAULT_CHARGE_EFFICIENCY = 0.90
DEFAULT_DISCHARGE_EFFICIENCY = 0.90

# Islanding safety gate (see powerwall.py's PowerwallIslandingBlockedError) -
# options-flow only, not initial setup, since these are safety tuning knobs
# most installs never need to touch. Defaults (DEFAULT_MIN_SOC_FOR_ISLANDING,
# DEFAULT_MAX_ISLANDING_HOURS_PER_DAY) live in powerwall.py itself rather
# than being duplicated here, since that module already exported them before
# this options step existed and other code imports them from there.
CONF_MIN_SOC_FOR_ISLANDING = "min_soc_for_islanding"
CONF_MAX_ISLANDING_HOURS_PER_DAY = "max_islanding_hours_per_day"
