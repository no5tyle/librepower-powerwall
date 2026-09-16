# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 LibrePower contributors
# Full license: /LICENSE. Third-party exception (this file is NOT it): /NOTICE.

"""Tesla RSA key pairing for Powerwall local control (v1r).

STATUS: this module's OAuth history in one paragraph, for anyone diffing
against an older copy. It originally drove Tesla's "Owner API" login
directly (client_id ``ownerapi``) - that broke when Tesla decommissioned
that domain for third-party callers in June 2026 (HTTP 403 on every call).
Reviving it with our own OAuth app would have meant a registered Tesla
developer/business account, a hosted `.well-known` public key, and ongoing
custody of every user's refresh token - real infrastructure this project
isn't set up to run. Rewritten instead to bootstrap through an **existing**
Home Assistant `teslemetry` config entry: the user authenticates with
Teslemetry once (a service that already holds a registered, Tesla-approved
Fleet API developer app), and this module drives the same Tesla RSA-pairing
protocol using that entry's already-authenticated per-site API client -
no OAuth flow, token storage, or hosted infrastructure of our own at all.

Deliberately decoupled from Teslemetry specifically: every function here
takes a ``site_api`` object as a plain duck-typed argument (an object
exposing ``add_authorized_client``/``list_authorized_clients``/
``get_system_info`` async methods - tesla_fleet_api's ``EnergySite`` shape,
which Teslemetry's own per-site client already implements). Only
config_flow.py imports Teslemetry/tesla_fleet_api directly to actually
obtain that object; this module would work unchanged against any other
broker exposing the same shape (a self-registered Fleet API app, some
future alternative), or a fake in a test.

Registers a public key with Tesla so the Gateway will accept RSA-signed
"v1r" commands from us over the local network - this is what unlocks
``async_charge``/``async_discharge``/curtailment/islanding in powerwall.py;
without it every write raises ``PowerwallV1rRequiredError``. Unlike gateway-
password mode, this path needs no local Gateway password at all, at any
step - not even to look up the physical DIN, which is read via Teslemetry's
cloud API (``get_system_info``) rather than a locally-authenticated call
(contrast Teslemetry's own ``hass-powerwall-v1r`` companion integration,
which discovers the DIN through ``aiopowerwall``'s local, password-
authenticated ``connect()`` instead - a legitimate different choice for a
project bundling its own local transport, but unnecessary for us since
``powerwall_v1r.py`` already talks to the Gateway with no password. This
also sidesteps gateway-password mode's own current failure: some PW3 +
Backup Gateway 2 firmware (confirmed 26.x) rejects the local TEDAPI login
outright regardless of password correctness - see
https://github.com/jasonacox/pypowerwall/issues/284. RSA-signed v1r queries
are a different wire path, unaffected by that specific lockdown.

Flow:
    1. Generate an RSA-4096 keypair (blocking; run via executor -
       ``generate_rsa_keypair``'s own PowerSync-sourced timing note still
       applies: ~1-3s on typical HA hardware). Format (PEM
       TraditionalOpenSSL private key, DER PKCS1 public key) confirmed to
       match ``tesla_fleet_api``'s own ``get_rsa_private_key``/
       ``rsa_public_der_pkcs1`` exactly - the format Tesla's gateway
       actually expects, not just tested against our own send path.
    2. config_flow.py obtains an already-authenticated ``site_api`` for the
       chosen energy site from the user's existing ``teslemetry`` config
       entry - no login step of our own.
    3. ``async_get_din`` reads the Gateway's physical DIN via Teslemetry's
       cloud ``get_system_info`` call.
    4. ``async_register_key`` submits the public key
       (``add_authorized_client_request``). Tesla sometimes auto-verifies
       from the cloud step alone; if not, the user must physically toggle
       the Gateway's DC isolator off-then-on as physical-presence proof
       within roughly a 2-minute window of registration, after which
       ``async_poll_key_state`` (``list_authorized_clients_request``) shows
       the key's state flip from PENDING to VERIFIED.
    5. Nothing from Teslemetry is persisted - once the key is VERIFIED, all
       future v1r calls are local-only (RSA-signed against the Gateway
       directly, via ``powerwall_v1r.py``), so there's nothing further to
       keep from Teslemetry's cloud. Only the PEM private key and the
       Gateway DIN get saved (into the config entry - see __init__.py's
       ``_async_ensure_rsa_key_file``).

The state values, key/client type constants, and gRPC-command payload shape
below (``key_type``/``authorized_client_type``/state ints, the
``authorization``/``add_authorized_client_request``/
``list_authorized_clients_request`` command names) were originally
reverse-engineered against the dead Owner API and flagged as "not validated
against live hardware." Cross-checked now against ``tesla_fleet_api``'s own
(actively maintained, hardware-tested via Teslemetry's real user base)
``AuthorizedClientKeyType``/``AuthorizedClientType``/``AuthorizedClientState``
enums and ``EnergySite._command`` payload shape - every value matches
exactly, so that reverse-engineering held up. Kept as local constants here
rather than importing ``tesla_fleet_api.const`` directly, to keep this
module's only real dependency (site_api's duck-typed shape) at the config
flow layer, not baked into the protocol-driving logic itself.
"""
from __future__ import annotations

import base64
import hashlib
import logging
from dataclasses import dataclass
from typing import Any

_LOGGER = logging.getLogger(__name__)

# Key state values returned by add_authorized_client_request /
# list_authorized_clients_request - matches tesla_fleet_api's
# AuthorizedClientState exactly (cross-checked, see module docstring).
STATE_PENDING = 1
STATE_PENDING_VERIFICATION = 2
STATE_VERIFIED = 3

# add_authorized_client_request's key_type/authorized_client_type - matches
# tesla_fleet_api's AuthorizedClientKeyType.RSA /
# AuthorizedClientType.CUSTOMER_MOBILE_APP exactly (cross-checked). Passed
# explicitly below even though they're also site_api's own defaults, so a
# future tesla_fleet_api default change can't silently change what we
# register.
_KEY_TYPE_RSA = 1
_AUTHORIZED_CLIENT_TYPE_CUSTOMER_MOBILE_APP = 1


class PairingError(Exception):
    """Base error for the pairing flow."""


class PairingAuthError(PairingError):
    """Teslemetry/Tesla rejected the registration or lookup request."""


@dataclass(frozen=True, slots=True)
class RsaKeypair:
    """A freshly generated (or loaded) v1r signing key."""

    private_key_pem: str
    public_key_der: bytes

    @property
    def fingerprint_sha256(self) -> str:
        return hashlib.sha256(self.public_key_der).hexdigest()


@dataclass(slots=True)
class PairingResult:
    """What gets persisted into the config entry on success."""

    private_key_pem: str
    din: str
    site_name: str
    verified: bool


# -- RSA keygen (blocking - run via hass.async_add_executor_job) ------------


def generate_rsa_keypair() -> RsaKeypair:
    """Generate a fresh RSA-4096 keypair for v1r signing. Blocking."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.PKCS1
    )
    return RsaKeypair(private_key_pem=private_pem, public_key_der=public_der)


# -- Tesla RSA-pairing protocol, driven through an already-authenticated
#    site_api (see module docstring for the duck-typed shape) --------------


async def async_get_din(site_api: Any) -> str | None:
    """Look up the Gateway's physical DIN via Teslemetry's cloud API.

    No local Gateway login/password needed - unlike Teslemetry's own
    hass-powerwall-v1r companion, which discovers the DIN via a locally-
    authenticated aiopowerwall.connect() call instead (see module
    docstring).

    Field path confidence: ``("response", "din")`` (checked first) is the
    flat shape, matching what list_authorized_clients was confirmed to
    actually return live (see _extract_key_state's own note) - a live
    capture of get_system_info's own response would be needed to be fully
    sure it's shaped the same way rather than nesting "din" one level
    deeper, but it's a reasonable inference from a sibling call on the
    same API. The deep gRPC-envelope paths are kept as a fallback only
    (the original, now-disproven-for-list_authorized_clients guess),
    checked both PascalCase and snake_case since that inconsistency has
    been observed elsewhere in these responses.
    """
    response = await site_api.get_system_info()
    for path in (
        ("response", "din"),
        ("response", "message", "Payload", "Common", "Message", "GetSystemInfoResponse", "din"),
        ("response", "message", "payload", "common", "message", "get_system_info_response", "din"),
    ):
        value = _dig(response, path)
        if isinstance(value, str) and value:
            return value
    # Same reasoning as async_poll_key_state's own WARNING log: a
    # get_system_info response we can't find "din" in at all is worth
    # seeing in full - this call's actual shape has never been captured
    # live (unlike list_authorized_clients, whose capture is what found
    # the bug these field-path guesses were fixed against).
    _LOGGER.warning(
        "Could not find the Gateway DIN in Teslemetry's get_system_info "
        "response - full response for diagnosis: %s",
        response,
    )
    return None


async def async_register_key(site_api: Any, keypair: RsaKeypair) -> int | None:
    """Submit the public key for registration. Returns the state if known.

    Exceptions from ``site_api`` (tesla_fleet_api's ``TeslaFleetError``
    hierarchy) propagate unwrapped - config_flow.py, which already imports
    tesla_fleet_api to obtain site_api in the first place, is where those
    get caught and mapped to a user-facing error, not here (see module
    docstring on staying duck-typed/decoupled).
    """
    response = await site_api.add_authorized_client(
        keypair.public_key_der,
        description="LibrePower Powerwall adapter",
        key_type=_KEY_TYPE_RSA,
        authorized_client_type=_AUTHORIZED_CLIENT_TYPE_CUSTOMER_MOBILE_APP,
    )
    state = _extract_key_state(response, keypair.public_key_der)
    if state is None:
        # Same reasoning as async_poll_key_state's own WARNING log - a
        # registration response we can't parse the state out of is worth
        # seeing in full, not silently swallowed.
        _LOGGER.warning(
            "Could not read a state back from key registration - full "
            "response for diagnosis: %s",
            response,
        )
    return state


async def async_poll_key_state(site_api: Any, keypair: RsaKeypair) -> int | None:
    """One check of whether the key has reached VERIFIED yet.

    A single attempt, not a loop - the caller (config_flow.py) drives
    retries via its own form re-submission (or a short bounded sleep loop,
    matching hass-powerwall-v1r's own pattern) so a slow Tesla response
    never blocks a config flow step indefinitely.
    """
    response = await site_api.list_authorized_clients()
    state = _extract_key_state(response, keypair.public_key_der)
    if state is None:
        # Either our key isn't in the response at all yet, or it is but
        # _extract_key_state's field-path guesses didn't match how this
        # response is actually shaped - not yet confirmed against live
        # hardware (see this module's own docstring). Logged at WARNING
        # (not DEBUG) specifically so it shows up without the user needing
        # to first enable debug logging - if Tesla's own app confirms
        # pairing succeeded but this keeps returning None, this line is
        # what tells us whether the key truly isn't listed yet or our
        # parsing just doesn't recognise the shape it came back in.
        _LOGGER.warning(
            "Pairing key not found as VERIFIED in Teslemetry's response - "
            "full response for diagnosis: %s",
            response,
        )
    return state


# -- internals ----------------------------------------------------------------


def _extract_key_state(resp: dict[str, Any], pubkey_der: bytes) -> int | None:
    """Pull this key's registration state out of Teslemetry's response.

    Confirmed live (via async_poll_key_state's/async_register_key's own
    diagnostic WARNING logs, against real Teslemetry responses) that
    there's no gRPC envelope at all, but the two calls don't even share
    one flat shape with each other:

        # list_authorized_clients - a wrapped list
        {"response": {"clients": [{"public_key": ..., "state": ..., ...}, ...]}}

        # add_authorized_client - the single client's own fields
        # flattened directly onto "response", no wrapping key at all
        {"response": {"public_key": ..., "state": ..., ...}}

    Both confirmed live, not guessed - the second shape was this module's
    first real miss even after the initial live-response fix: it assumed
    a single client would still be wrapped in a "client" key (a
    reasonable-looking guess that turned out wrong), which is kept below
    as a secondary check in case some response ever is shaped that way,
    but response-itself-is-the-client is what add_authorized_client
    actually sends and is checked first, right after the wrapped-list
    shape. This module's *original* guess - a deep
    ``response.message.payload.authorization.message...`` gRPC-over-JSON
    envelope, reverse-engineered against the dead Owner API and never
    seen in any real Teslemetry response - is kept furthest down as a
    last-resort fallback only.
    """
    response = resp.get("response") if isinstance(resp, dict) else None
    if isinstance(response, dict):
        clients: list[Any] | None = None
        if isinstance(response.get("clients"), list):
            clients = response["clients"]
        elif isinstance(response.get("client"), dict):
            clients = [response["client"]]
        elif "public_key" in response or "PublicKey" in response:
            # add_authorized_client's actual confirmed shape: response
            # itself carries the client's fields directly, no wrapper.
            clients = [response]

        if clients is not None:
            state = _find_state_by_pubkey(clients, pubkey_der)
            if state is not None:
                return state

    # --- fallback: the original deep gRPC-envelope guess (unconfirmed) ---
    msg = _dig(resp, ("response", "message", "Payload", "Authorization", "Message"))
    if msg is None:
        msg = _dig(resp, ("response", "message", "payload", "authorization", "message"))
    if msg is None:
        return None

    for key in ("AddAuthorizedClientResponse", "add_authorized_client_response"):
        if key in msg:
            client = msg[key].get("client") or msg[key].get("Client")
            if client:
                state = client.get("state", client.get("State"))
                if state is not None:
                    return int(state)

    for key in ("ListAuthorizedClientsResponse", "list_authorized_clients_response"):
        if key in msg:
            clients = msg[key].get("clients") or msg[key].get("Clients") or []
            state = _find_state_by_pubkey(clients, pubkey_der)
            if state is not None:
                return state

    return None


def _find_state_by_pubkey(clients: list[Any], pubkey_der: bytes) -> int | None:
    """Match a client entry by public key (so a different already-
    authorized key - e.g. the Tesla app's own, or a stale key from an
    earlier attempt - can't produce a false positive) and return its
    ``state``. Handles both PascalCase and snake_case field names, since
    Tesla's responses have been observed with both depending on
    endpoint/firmware version.
    """
    for client in clients:
        if not isinstance(client, dict):
            continue
        client_pubkey = client.get("public_key") or client.get("PublicKey")
        if not client_pubkey:
            continue
        try:
            if base64.b64decode(client_pubkey) != pubkey_der:
                continue
        except Exception as err:  # noqa: BLE001 - malformed field, not our key
            _LOGGER.debug("Skipping unparseable client public_key: %s", err)
            continue
        state = client.get("state", client.get("State"))
        if state is not None:
            return int(state)
    return None


def _dig(obj: Any, path: tuple[str, ...]) -> Any:
    for key in path:
        if not isinstance(obj, dict) or key not in obj:
            return None
        obj = obj[key]
    return obj
