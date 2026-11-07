"""Local Ed25519 signing key and token minting for NetBird identity JWTs.

This mimics what the NetBird proxy does in "jwt" forwarding mode, so you can
build and test an app without NetBird running. The key lives in dev/keys/,
which is gitignored. It is a test key: never use it in production.
"""

import hashlib
import json
import os
import secrets
import time
from base64 import urlsafe_b64encode
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

KEY_DIR = Path(os.environ.get("NETBIRD_DEV_KEY_DIR", Path(__file__).parent / "keys"))
KEY_FILE = KEY_DIR / "signing-key.pem"
PUBLIC_FILE = KEY_DIR / "public-key.pem"

# Example role mapping used by the presets below. It mirrors the example in
# the README: admin <- group ops, viewer <- group eng, API keys get "agent".
PRESETS = {
    "admin": {
        "sub": "usr_alice",
        "email": "alice@example.com",
        "groups": ["ops", "eng"],
        "roles": ["admin", "viewer", "editor"],
        "mcp_tools": ["*"],
        "auth_method": "oidc",
    },
    "viewer": {
        "sub": "usr_bob",
        "email": "bob@example.com",
        "groups": ["eng"],
        "roles": ["viewer"],
        "mcp_tools": ["list_*", "get_ticket"],
        "auth_method": "oidc",
    },
    "agent": {
        # API key callers: one synthetic user id, no email, no groups.
        "sub": "header-user",
        "email": "",
        "groups": [],
        "roles": ["agent"],
        "mcp_tools": ["list_*"],
        "auth_method": "header",
    },
    "nobody": {
        "sub": "usr_carol",
        "email": "carol@example.com",
        "groups": ["contractors"],
        "roles": [],
        "mcp_tools": [],
        "auth_method": "oidc",
    },
}


def load_or_create_key() -> Ed25519PrivateKey:
    """Return the dev signing key, creating it on first use."""
    if KEY_FILE.exists():
        key = serialization.load_pem_private_key(KEY_FILE.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise SystemExit(f"{KEY_FILE} is not an Ed25519 key")
        return key

    KEY_DIR.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    PUBLIC_FILE.write_text(public_pem(key))
    return key


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def public_pem(key: Ed25519PrivateKey) -> str:
    """PKIX PEM, the same format NetBird shows as public_key_pem."""
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def key_id(key: Ed25519PrivateKey) -> str:
    """Same derivation as the proxy: first 8 bytes of sha256(pubkey), hex."""
    return hashlib.sha256(_raw_public(key)).hexdigest()[:16]


def jwks(key: Ed25519PrivateKey) -> dict:
    """The JWKS document the proxy serves at /.well-known/netbird/jwks.json."""
    x = urlsafe_b64encode(_raw_public(key)).rstrip(b"=").decode()
    return {
        "keys": [
            {"kty": "OKP", "crv": "Ed25519", "x": x, "kid": key_id(key), "alg": "EdDSA", "use": "sig"}
        ]
    }


def mint(
    key: Ed25519PrivateKey,
    domain: str,
    sub: str,
    email: str = "",
    groups: list[str] | None = None,
    roles: list[str] | None = None,
    mcp_tools: list[str] | None = None,
    auth_method: str = "oidc",
    ttl: int = 60,
    issuer: str | None = None,
) -> str:
    """Mint a token shaped exactly like the proxy's (empty fields omitted)."""
    now = int(time.time())
    claims: dict = {
        "iss": issuer or f"https://{domain}",
        "aud": [domain],
        "sub": sub,
        "jti": secrets.token_hex(16),
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
        "roles": roles or [],
    }
    if ttl <= 0:
        # An already-expired token: back-date everything so only exp fails.
        claims["iat"] = claims["nbf"] = now + ttl - 60
    if email:
        claims["email"] = email
    if groups:
        claims["groups"] = groups
    if mcp_tools:
        claims["mcp_tools"] = mcp_tools
    if auth_method:
        claims["auth_method"] = auth_method
    return jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": key_id(key)})


def jwks_json(key: Ed25519PrivateKey) -> str:
    return json.dumps(jwks(key), indent=2)
