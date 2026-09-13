# LibrePower - Powerwall

The Tesla Powerwall battery adapter for [LibrePower](https://github.com/YOURNAME/librepower).

This is intentionally a small, separate repo. It exists so that installing
Powerwall support doesn't mean receiving updates for Sigenergy, Sungrow, or
any other battery brand's code you don't have — the exact HACS-update-noise
problem that motivated splitting this out of a single monolithic integration
in the first place.

**This repo does nothing on its own.** It requires [LibrePower
core](https://github.com/YOURNAME/librepower) to be installed and set up
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
transport, which requires a one-time RSA key registered through Tesla's Fleet
API — a real, separate step, not yet built into this repo's config flow. See
`powerwall.py`'s module docstring for the full detail on what does and
doesn't need the cloud.

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

- **No unregister path.** If this integration is removed while core keeps
  running, core has no way to know the battery is gone — its coordinator
  just keeps a stale `BatteryClient` reference that will start failing calls.
  Worth fixing before relying on this in a setup where the adapter might be
  uninstalled independently of core.
- **Control setting isn't live-reloaded.** `read_only` is decided once, from
  core's `control_enabled` option, at this integration's own setup time. If
  you change core's control setting afterwards, this integration needs a
  manual reload to pick it up — not yet automated.
- **v1r pairing flow isn't built.** Control requires it (see above); nothing
  in this repo's config flow walks you through Tesla's RSA key registration
  yet.

## Licensing

GPLv3-or-later — same as core, and for the same reason: this repo imports
directly from core's GPL-licensed code, so GPL-to-GPL is the natural fit with
no compatibility question to resolve (unlike core's own MIT exception for its
vendored optimiser). See `NOTICE` for the pypowerwall runtime-dependency
credit.
