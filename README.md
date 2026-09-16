# LibrePower - Powerwall

The Tesla Powerwall battery adapter for [LibrePower](https://github.com/no5tyle/librepower).

This is intentionally a small, separate repo. It exists so that installing
Powerwall support doesn't mean receiving updates for Sigenergy, Sungrow, or
any other battery brand's code you don't have — the exact HACS-update-noise
problem that motivated splitting this out of a single monolithic integration
in the first place.

**This repo does nothing on its own.** It requires [LibrePower
core](https://github.com/no5tyle/librepower) to be installed and set up
first — that's where the optimiser, pricing, and dashboard live. This repo's
only job is connecting to a Powerwall and reporting its telemetry and control
surface to core.

## Installing via HACS

1. Install and set up **LibrePower core** first (see its own README)
2. HACS → three-dot menu → **Custom repositories** → add this repo's URL, category **Integration**
3. Download, restart Home Assistant
4. Settings → Devices & Services → **Add Integration** → LibrePower - Powerwall
5. Pick which LibrePower core instance this Powerwall belongs to (skipped automatically if you only have one)
6. If you have Home Assistant's official **Teslemetry** integration set up with a battery-capable energy site, you'll be offered a choice: pair via Teslemetry (no Gateway password needed) or enter the Gateway address and password directly. Otherwise you'll go straight to the Gateway address/password form.

## How it works

Wraps [pypowerwall](https://github.com/jasonacox/pypowerwall) (MIT) for local
**gateway-password TEDAPI** access — no Tesla account needed for telemetry.
Control (backup reserve, export rule, islanding) needs pypowerwall's **v1r**
transport, which requires a one-time RSA key registered through Tesla.

Two ways to get that key registered:

- **Gateway password mode**: works everywhere pypowerwall's TEDAPI reaches,
  but as of some Powerwall 3 + Backup Gateway 2 firmware (confirmed 26.x),
  local TEDAPI login is rejected outright regardless of password correctness
  — see [jasonacox/pypowerwall#284](https://github.com/jasonacox/pypowerwall/issues/284).
  Not something fixable from this repo.
- **Pair via Teslemetry**: no Gateway password needed, at any step - even
  the Gateway's physical DIN is read via Teslemetry's cloud API rather than
  a local login. Bootstraps the same RSA-pairing protocol this repo briefly
  drove via Tesla's own "Owner API" (decommissioned for third-party callers
  in June 2026, which is why that path was pulled) through an *existing*
  [Teslemetry](https://teslemetry.com) config entry instead — Teslemetry
  already holds a registered, Tesla-approved Fleet API app, so this repo
  never needs one of its own (no business account, no hosted redirect URI,
  no custody of your Tesla tokens). Teslemetry is only touched during the
  one-time pairing handshake; once the key is VERIFIED, everything is local
  again via the same `powerwall_v1r.py` gateway-password mode already used.
  Mirrors the exact pattern Teslemetry's own official companion integration,
  [`hass-powerwall-v1r`](https://github.com/Teslemetry/hass-powerwall-v1r),
  uses for the same purpose. See `pairing.py`'s module docstring for the
  full design and its (deliberate) zero hard dependency on
  Teslemetry/`tesla_fleet_api` at import time.

Battery capacity and max charge/discharge power are entered during setup,
not auto-detected — pypowerwall has no API to read nameplate capacity from
the device (confirmed by checking; there isn't one). Use your Powerwall's
rated spec (13,500 Wh per unit is standard for PW2/PW+/PW3).

## The contract with core

This repo depends on `librepower` core (`"dependencies": ["librepower"]` in
`manifest.json`, which guarantees load order) and imports its `BatteryClient`
contract directly:

```python
from custom_components.librepower.battery import (
    BatteryCapabilities, BatteryClient, BatterySnapshot, ...
)
```

This relies on Home Assistant loading every custom_component under a shared
`custom_components` namespace package — true today, not an HA-core-blessed
stable API. Worth re-verifying if a future HA release changes integration
loading.

**Verified in this repo's development** (via a constructed namespace-package
sandbox mimicking HA's real loader, with a minimal `homeassistant` stub — not
a live HA install):
- `PowerwallClient` genuinely satisfies core's `BatteryClient` Protocol
  (`isinstance()` check passes)
- This adapter's specific exceptions (`PowerwallReadOnlyError`,
  `PowerwallV1rRequiredError`) are correctly caught by core's generic
  exception types (`BatteryReadOnlyError`, `BatteryControlUnavailableError`)
- Registering a battery correctly overwrites the optimiser's placeholder
  capacity/charge-limit defaults with this adapter's reported real values

**Not yet verified: an actual live Home Assistant install with both
integrations running together.** The above confirms the import graph and
type contracts are sound: it does not confirm HA's real config-entry
lifecycle, options-reload timing, or storage behave as expected end to end.

## Known gaps

- **v1r pairing via Teslemetry has been exercised against real hardware,
  including a real bug found and fixed this way.** `pairing.py`'s payload
  structure and state/type constants were cross-checked field-for-field
  against `tesla_fleet_api`'s own request-building code and matched
  exactly, but the *response* shape was still a guess - and turned out to
  be wrong: `_extract_key_state` assumed a deep gRPC-over-JSON envelope
  (reverse-engineered against the old, now-dead Owner API), but a real
  captured response showed Teslemetry actually returns a flat
  `{"response": {"clients": [...]}}` shape with no envelope at all. Fixed
  and confirmed against that real captured response (kept as a literal
  test fixture). `async_get_din`'s field path was hardened the same way
  as a precaution but hasn't itself been captured live yet - both
  `async_poll_key_state`/`async_register_key` and `async_get_din` now log
  the full raw response at WARNING level if they can't find what they're
  looking for, so any remaining shape mismatch surfaces immediately in
  the Home Assistant log rather than as a silent "still pending".
- **`powerwall_v1r.py`'s DeviceControllerQuery field parsing (SOC, power
  flows, grid status, alerts) is cross-referenced against pypowerwall's own
  and PowerSync's independent implementations, not validated against live
  hardware by this repo.** Unlike the pairing response shape above, this
  is the *local* v1r query path (after pairing completes) and hasn't been
  exercised against real hardware yet - re-verify once pairing reaches
  that step end to end.

## Licensing

GPLv3-or-later — same as core, and for the same reason: this repo imports
directly from core's GPL-licensed code, so GPL-to-GPL is the natural fit with
no compatibility question to resolve (unlike core's own MIT exception for its
vendored optimiser). See `NOTICE` for the pypowerwall runtime-dependency
credit.
