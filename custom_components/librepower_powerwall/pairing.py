# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 LibrePower contributors
# Full license: /LICENSE. Third-party exception (this file is NOT it): /NOTICE.

"""Tesla RSA key pairing for Powerwall local control (v1r).

Registers a public key with Tesla so the Gateway will accept RSA-signed
"v1r" commands from us over the local network - this is what unlocks
``async_charge``/``async_discharge``/curtailment/islanding in powerwall.py;
without it every write raises ``PowerwallV1rRequiredError``. It does **not**
remove the need for the gateway password: pypowerwall's own docs are explicit
that ``gw_pwd`` is used for both plain TEDAPI reads and v1r writes. This is
additive scope, not a way to avoid opening the Powerwall - see powerwall.py's
module docstring.

Auth path: Tesla's "Owner API" login only (client_id ``ownerapi``, the same
OAuth client Tesla's own mobile app uses) - just the user's Tesla account
email/password via a normal Tesla login page, no developer app, no hosted
redirect URI, no broker of our own to run. This mirrors what pypowerwall's
own ``v1r_register.py`` recommends as its default path; that script is a
blocking interactive CLI tool though (raw ``input()`` prompts, a native
WebView), so it isn't reusable as-is inside an async Home Assistant config
flow. This module reimplements just the protocol - PKCE login, key
generation, registration, verification polling - against the same public
Tesla endpoints, using httpx instead so the calls stay async and HA's event
loop is never blocked.

Flow, matching Tesla's actual handshake:
    1. Generate an RSA-4096 keypair (blocking; run via executor - PowerSync's
       own docs put this at ~1-3s on typical HA hardware).
    2. PKCE login against ``auth.tesla.com`` (``ownerapi`` client) - the user
       opens a URL, logs in, and pastes back the (intentionally broken)
       ``tesla://auth/callback?code=...`` redirect URL from their browser's
       address bar. Same technique as tesla_auth (Rust) and every
       reverse-engineered Tesla API client; nothing new invented here.
    3. Exchange the code for an access token, then call Tesla's legacy
       ``owner-api.teslamotors.com`` API (not the newer partner-gated Fleet
       API) to find the energy site + Gateway DIN and register the public
       key via ``add_authorized_client_request``.
    4. Tesla sometimes auto-verifies the key from the cloud step alone; if
       not, the user must physically toggle the Gateway's DC isolator
       off-then-on as physical-presence proof, after which polling
       ``list_authorized_clients_request`` shows the key's state flip from
       PENDING to VERIFIED.
    5. The access/refresh tokens are never persisted - once the key is
       VERIFIED, all future v1r calls are local-only (RSA-signed against the
       Gateway directly), so there's nothing further to keep from Tesla's
       cloud. Only the PEM private key and the Gateway DIN get saved (into
       the config entry - see __init__.py's ``_async_ensure_rsa_key_file``).

Why httpx instead of HA's shared aiohttp session: Tesla's auth and
owner-api.teslamotors.com endpoints now require HTTP/2, which aiohttp
doesn't support. httpx (with the h2 extra) does, natively async, no
executor needed. Both are pure Python - no C-extension wheel-availability
risk like the optimiser's old cvxpy dependency had.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

_LOGGER = logging.getLogger(__name__)

# -- Tesla Owner API OAuth (PKCE) constants ----------------------------------
# Matches tesla_auth (Rust) / pypowerwall's tesla_auth.py exactly - this is
# Tesla's own mobile app's OAuth client, not something we registered.
CLIENT_ID = "ownerapi"
AUTH_HOST = "https://auth.tesla.com"
AUTHORIZE_PATH = "/oauth2/v3/authorize"
TOKEN_PATH = "/oauth2/v3/token"
REDIRECT_URI = "tesla://auth/callback"
SCOPES = "openid email offline_access"

# Legacy owner API - accepts Owner-API-scoped tokens for the same
# energy_sites command endpoint the newer partner-gated Fleet API exposes.
OWNER_API_BASE = "https://owner-api.teslamotors.com"

# Key state values returned by add_authorized_client_request /
# list_authorized_clients_request.
STATE_PENDING = 1
STATE_PENDING_VERIFICATION = 2
STATE_VERIFIED = 3

_HTTP_TIMEOUT = 30.0


class PairingError(Exception):
    """Base error for the pairing flow."""


class PairingAuthError(PairingError):
    """Tesla rejected the login or the pasted-back redirect URL."""


class PairingSiteNotFoundError(PairingError):
    """No energy site (Powerwall) found on this Tesla account."""


@dataclass(frozen=True, slots=True)
class PkceChallenge:
    """One PKCE login attempt's verifier/challenge/state triple."""

    verifier: str
    challenge: str
    state: str


@dataclass(frozen=True, slots=True)
class EnergySite:
    """One Tesla energy site (Powerwall installation) found on the account."""

    site_id: str
    din: str
    name: str


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


# -- step 1: PKCE login -------------------------------------------------------


def build_pkce_challenge() -> PkceChallenge:
    """Generate a fresh PKCE verifier/challenge/state triple.

    Matches tesla_auth exactly: verifier is 32 random bytes, challenge is its
    SHA-256, both urlsafe-base64 without padding.
    """
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    state = secrets.token_urlsafe(16)
    return PkceChallenge(verifier=verifier, challenge=challenge, state=state)


def build_authorize_url(challenge: PkceChallenge) -> str:
    """The URL the user opens in their own browser to log in to Tesla."""
    params = {
        "client_id": CLIENT_ID,
        "code_challenge": challenge.challenge,
        "code_challenge_method": "S256",
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPES,
        "state": challenge.state,
    }
    return f"{AUTH_HOST}{AUTHORIZE_PATH}?" + urllib.parse.urlencode(params)


def parse_authorization_code(redirect_url: str, expected_state: str) -> str:
    """Pull the ``code`` param out of the pasted-back redirect URL.

    Tesla redirects to ``tesla://auth/callback?code=...&state=...`` after
    login - no real app handles that scheme in a browser, so the page fails
    to load and the user copies the attempted URL from their address bar
    (or an "open in app?" prompt) instead. We only need the query string, so
    a browser mangling the scheme/host doesn't matter - only the params do.
    """
    redirect_url = redirect_url.strip()
    if not redirect_url:
        raise PairingAuthError("No URL was pasted in")

    parsed = urllib.parse.urlparse(redirect_url)
    params = urllib.parse.parse_qs(parsed.query)

    if "state" not in params or params["state"][0] != expected_state:
        raise PairingAuthError(
            "The pasted URL's 'state' doesn't match this login attempt - "
            "paste the URL from the login you just completed, not an old one"
        )
    if "code" not in params:
        error = params.get("error_description", params.get("error", ["unknown"]))[0]
        raise PairingAuthError(f"No authorization code in that URL ({error})")

    return params["code"][0]


# -- step 2: token exchange, energy site lookup, key registration -----------


async def async_exchange_code(code: str, verifier: str) -> str:
    """Exchange the authorization code for an access token.

    Returns the access token only - the refresh token is deliberately
    discarded (see module docstring: nothing further to keep from Tesla's
    cloud once the key is verified).
    """
    httpx = _require_httpx()
    payload = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": REDIRECT_URI,
    }
    async with httpx.AsyncClient(http2=True, timeout=_HTTP_TIMEOUT) as client:
        resp = await client.post(f"{AUTH_HOST}{TOKEN_PATH}", json=payload)
    data = _json_or_raise(resp, "Token exchange")
    access_token = data.get("access_token")
    if not access_token:
        raise PairingAuthError(f"No access_token in Tesla's response: {data}")
    return access_token


async def async_get_energy_sites(access_token: str) -> list[EnergySite]:
    """List Powerwall/energy sites on this Tesla account."""
    httpx = _require_httpx()
    async with httpx.AsyncClient(http2=True, timeout=_HTTP_TIMEOUT) as client:
        resp = await client.get(
            f"{OWNER_API_BASE}/api/1/products",
            headers=_auth_header(access_token),
        )
    data = _json_or_raise(resp, "Listing energy sites")

    sites: list[EnergySite] = []
    for product in data.get("response", []) or []:
        site_id = product.get("energy_site_id")
        if site_id is None:
            continue  # a vehicle or other non-energy product
        sites.append(
            EnergySite(
                site_id=str(site_id),
                din=str(product.get("gateway_id", "unknown")),
                name=str(product.get("site_name", "Powerwall")),
            )
        )

    if not sites:
        raise PairingSiteNotFoundError(
            "No energy site found on this Tesla account - is this the same "
            "account the Powerwall is set up under?"
        )
    return sites


async def async_register_key(access_token: str, site: EnergySite, keypair: RsaKeypair) -> int | None:
    """Submit the public key for registration. Returns the state if known."""
    httpx = _require_httpx()
    payload = {
        "command_properties": {
            "message": {
                "authorization": {
                    "add_authorized_client_request": {
                        "key_type": 1,
                        "public_key": base64.b64encode(keypair.public_key_der).decode(),
                        "authorized_client_type": 1,
                        "description": "LibrePower Powerwall adapter",
                    }
                }
            },
            "identifier_type": 1,
        },
        "command_type": "grpc_command",
    }
    async with httpx.AsyncClient(http2=True, timeout=_HTTP_TIMEOUT) as client:
        resp = await client.post(
            f"{OWNER_API_BASE}/api/1/energy_sites/{site.site_id}/command",
            json=payload,
            headers=_auth_header(access_token),
        )
    data = _json_or_raise(resp, "Key registration")
    return _extract_key_state(data, keypair.public_key_der)


async def async_poll_key_state(
    access_token: str, site: EnergySite, keypair: RsaKeypair
) -> int | None:
    """One check of whether the key has reached VERIFIED yet.

    A single attempt, not a loop - the caller (the options flow) drives
    retries via its own form re-submission so a slow Tesla response never
    blocks a config flow step for longer than one HTTP call, and the user
    can back out at any point instead of being stuck behind a fixed sleep.
    """
    httpx = _require_httpx()
    payload = {
        "command_properties": {
            "message": {"authorization": {"list_authorized_clients_request": {}}},
            "identifier_type": 1,
        },
        "command_type": "grpc_command",
    }
    async with httpx.AsyncClient(http2=True, timeout=_HTTP_TIMEOUT) as client:
        resp = await client.post(
            f"{OWNER_API_BASE}/api/1/energy_sites/{site.site_id}/command",
            json=payload,
            headers=_auth_header(access_token),
        )
    data = _json_or_raise(resp, "Key verification check")
    return _extract_key_state(data, keypair.public_key_der)


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


# -- internals ----------------------------------------------------------------


def _require_httpx():
    try:
        import httpx
    except ImportError as err:
        raise PairingError(
            "httpx is not installed - required for Tesla pairing (see manifest.json)"
        ) from err
    return httpx


def _auth_header(access_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {access_token}"}


def _json_or_raise(resp: Any, what: str) -> dict[str, Any]:
    if resp.status_code == 401:
        raise PairingAuthError(f"{what} failed: Tesla token expired or was rejected")
    if resp.status_code >= 400:
        raise PairingError(f"{what} failed (HTTP {resp.status_code}): {resp.text[:500]}")
    try:
        return resp.json()
    except ValueError as err:
        raise PairingError(f"{what}: Tesla returned a non-JSON response") from err


def _extract_key_state(resp: dict[str, Any], pubkey_der: bytes) -> int | None:
    """Pull this key's registration state out of Tesla's (inconsistently
    cased) nested response shape.

    Tesla's gRPC-over-JSON envelope has been observed with both PascalCase
    and snake_case field names depending on endpoint/firmware version, so
    every level is checked both ways rather than assumed.
    """
    msg = _dig(resp, ("response", "message", "Payload", "Authorization", "Message"))
    if msg is None:
        msg = _dig(resp, ("response", "message", "payload", "authorization", "message"))
    if msg is None:
        return None

    # A fresh registration response: AddAuthorizedClientResponse.client.state
    for key in ("AddAuthorizedClientResponse", "add_authorized_client_response"):
        if key in msg:
            client = msg[key].get("client") or msg[key].get("Client")
            if client:
                state = client.get("state", client.get("State"))
                if state is not None:
                    return int(state)

    # A verification poll: ListAuthorizedClientsResponse.clients[].state,
    # matched by public key so a different already-verified key (e.g. the
    # Tesla app's own) can't produce a false positive.
    for key in ("ListAuthorizedClientsResponse", "list_authorized_clients_response"):
        if key in msg:
            clients = msg[key].get("clients") or msg[key].get("Clients") or []
            for client in clients:
                client_pubkey = client.get("public_key") or client.get("PublicKey")
                if not client_pubkey:
                    continue
                try:
                    if base64.b64decode(client_pubkey) != pubkey_der:
                        continue
                except Exception:  # noqa: BLE001 - malformed field, not our key
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
