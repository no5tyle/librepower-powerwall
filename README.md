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
6. Enter the Gateway address and password, plus your Powerwall's capacity and charge/discharge limits

## How it works

Wraps [pypowerwall](https://github.com/jasonacox/pypowerwall) (MIT) for local
**gateway-password TEDAPI** access — no Tesla account needed for telemetry.
Control (backup reserve, export rule, islanding) needs pypowerwall's **v1r**
transport, which requires a one-time RSA key registered through Tesla — real,
separate scope, and currently not reachable from this repo's config flow.
This repo briefly shipped a "pair with my Tesla account, no password needed"
setup path built on Tesla's Owner API; Tesla decommissioned that API for
third-party callers in June 2026, which broke the only login mechanism it
depended on, so it was pulled rather than left shipping a broken flow. The
RSA key registration and pure-v1r read/write client (`pairing.py`,
`powerwall_v1r.py`) are still correct and left in the repo - reviving the
feature needs a Fleet API developer app (Tesla business-account approval, a
real redirect URI) instead of a plain Tesla login. See `pairing.py`'s module
docstring for the detail.

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

- **Control setting isn't live-reloaded.** `read_only` is decided once, from
  core's `control_enabled` option, at this integration's own setup time. If
  you change core's control setting afterwards, this integration needs a
  manual reload to pick it up — not yet automated.
- **v1r pairing isn't wired into the UI.** `pairing.py` and `powerwall_v1r.py`
  implement RSA key registration and a password-free v1r read/write client,
  but the only login mechanism ever built for them (Tesla's Owner API) was
  decommissioned by Tesla in June 2026 - every call now returns HTTP 403.
  `powerwall.py` still picks pure-v1r mode automatically if an entry somehow
  has `rsa_key_path`/`din` set, but nothing in `config_flow.py` can produce
  those anymore. Reviving this needs a Fleet API developer app registration
  (business account, Tesla approval, a real redirect URI) swapped in for
  `pairing.py`'s login step - see that module's docstring.
- **`powerwall_v1r.py`'s DeviceControllerQuery field parsing (SOC, power
  flows, grid status, alerts) is cross-referenced against pypowerwall's own
  and PowerSync's independent implementations, not validated against live
  hardware by this repo.** Untested in practice since the only path that
  reached it (pair-first setup) is currently disabled - re-verify before
  reviving it.

## Licensing

GPLv3-or-later — same as core, and for the same reason: this repo imports
directly from core's GPL-licensed code, so GPL-to-GPL is the natural fit with
no compatibility question to resolve (unlike core's own MIT exception for its
vendored optimiser). See `NOTICE` for the pypowerwall runtime-dependency
credit.
