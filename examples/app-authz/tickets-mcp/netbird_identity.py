"""Read the caller's identity that the NetBird proxy forwards to your app.

Drop this one file into any Python app. It has two modes, set with
NETBIRD_IDENTITY_MODE:

  headers  Trust X-NetBird-User / -Groups / -User-Id / -Roles / -Auth-Method.
           Only safe when the NetBird proxy is the ONLY way to reach the app.
  jwt      Verify the signed token the proxy sends (default header
           X-NetBird-Identity, or Authorization: Bearer). Needs one of:
             NETBIRD_JWKS_URL        https://<domain>/.well-known/netbird/jwks.json
             NETBIRD_PUBLIC_KEY_PEM  the PEM text, or a path to a .pem file
           and NETBIRD_AUDIENCE=<service domain>.

Optional: NETBIRD_ISSUER (default https://<audience>), NETBIRD_JWT_HEADER
(default X-NetBird-Identity).

Usage:
  verifier = IdentityVerifier.from_env()
  ident = verifier.identify(request.headers)   # raises IdentityError if missing/invalid
  if not ident.has_role("admin"): return 403

The same file is used by whoami/ and tickets-mcp/. Keep the copies identical.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

import jwt

HEADER_USER = "X-NetBird-User"
HEADER_GROUPS = "X-NetBird-Groups"
HEADER_USER_ID = "X-NetBird-User-Id"
HEADER_ROLES = "X-NetBird-Roles"
HEADER_AUTH_METHOD = "X-NetBird-Auth-Method"
HEADER_IDENTITY = "X-NetBird-Identity"

# The proxy mints tokens with a 60s lifetime. Allow a little clock skew.
LEEWAY_SECONDS = 10
REQUIRED_CLAIMS = ["exp", "iat", "nbf", "iss", "aud", "sub"]


class IdentityError(Exception):
    """No usable identity on the request. Answer 401 and do not continue."""


@dataclass
class Identity:
    user_id: str
    email: str = ""
    groups: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    mcp_tools: list[str] = field(default_factory=list)
    auth_method: str = ""
    source: str = ""  # "jwt" or "headers"
    claims: dict[str, Any] | None = None  # verified JWT claims (jwt mode only)

    def has_role(self, *roles: str) -> bool:
        return any(r in self.roles for r in roles)

    def tool_allowed(self, tool: str) -> bool:
        return tool_allowed(self.mcp_tools, tool)

    @property
    def display_name(self) -> str:
        return self.email or self.user_id


def tool_allowed(patterns: list[str], tool: str) -> bool:
    """Same rule as the NetBird proxy: '*' matches any run of characters,
    every other character matches itself. Empty names never match."""
    if not tool:
        return False
    for p in patterns:
        regex = "".join(".*" if part == "*" else re.escape(part) for part in re.split(r"(\*)", p))
        if re.fullmatch(regex, tool, flags=re.DOTALL):
            return True
    return False


def _csv(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _load_pem(value: str) -> str:
    """Accept the PEM text itself or a path to a file holding it."""
    if "-----BEGIN" in value:
        return value.replace("\\n", "\n")
    with open(value, encoding="utf-8") as f:
        return f.read()


class IdentityVerifier:
    def __init__(
        self,
        mode: str,
        audience: str = "",
        issuer: str = "",
        jwks_url: str = "",
        public_key_pem: str = "",
        jwt_header: str = HEADER_IDENTITY,
    ):
        if mode not in ("headers", "jwt"):
            raise ValueError(f"NETBIRD_IDENTITY_MODE must be 'headers' or 'jwt', got {mode!r}")
        self.mode = mode
        self.jwt_header = jwt_header
        self._jwks = None
        self._key = None
        if mode != "jwt":
            return
        # Fail at startup, not per request: a jwt-mode app with no key would
        # otherwise reject everyone, or worse, be "fixed" by skipping checks.
        if not audience:
            raise ValueError("jwt mode needs NETBIRD_AUDIENCE (the service domain)")
        if bool(jwks_url) == bool(public_key_pem):
            raise ValueError("jwt mode needs exactly one of NETBIRD_JWKS_URL or NETBIRD_PUBLIC_KEY_PEM")
        if jwks_url and not jwks_url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
            raise ValueError("NETBIRD_JWKS_URL must be https:// (http is only accepted for localhost dev)")
        self.audience = audience
        self.issuer = issuer or f"https://{audience}"
        if jwks_url:
            self._jwks = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=300, timeout=5)
        else:
            self._key = jwt.PyJWK.from_dict(_pem_to_jwk(public_key_pem)).key

    @classmethod
    def from_env(cls, default_mode: str = "jwt") -> "IdentityVerifier":
        pem = os.environ.get("NETBIRD_PUBLIC_KEY_PEM", "")
        return cls(
            mode=os.environ.get("NETBIRD_IDENTITY_MODE", default_mode),
            audience=os.environ.get("NETBIRD_AUDIENCE", ""),
            issuer=os.environ.get("NETBIRD_ISSUER", ""),
            jwks_url=os.environ.get("NETBIRD_JWKS_URL", ""),
            public_key_pem=_load_pem(pem) if pem else "",
            jwt_header=os.environ.get("NETBIRD_JWT_HEADER", HEADER_IDENTITY),
        )

    def raw_token(self, headers: Mapping[str, str]) -> str:
        value = headers.get(self.jwt_header) or ""
        if self.jwt_header.lower() == "authorization":
            scheme, _, token = value.partition(" ")
            return token.strip() if scheme.lower() == "bearer" else ""
        return value.strip()

    def identify(self, headers: Mapping[str, str]) -> Identity:
        if self.mode == "jwt":
            return self._from_jwt(headers)
        return self.from_headers(headers)

    @staticmethod
    def from_headers(headers: Mapping[str, str]) -> Identity:
        user_id = (headers.get(HEADER_USER_ID) or "").strip()
        if not user_id:
            raise IdentityError("no X-NetBird-User-Id header: request did not come through NetBird")
        return Identity(
            user_id=user_id,
            email=(headers.get(HEADER_USER) or "").strip(),
            groups=_csv(headers.get(HEADER_GROUPS)),
            roles=_csv(headers.get(HEADER_ROLES)),
            auth_method=(headers.get(HEADER_AUTH_METHOD) or "").strip(),
            source="headers",
        )

    def _from_jwt(self, headers: Mapping[str, str]) -> Identity:
        token = self.raw_token(headers)
        if not token:
            raise IdentityError(f"no identity token in {self.jwt_header}")
        try:
            key = self._key if self._key is not None else self._jwks.get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                key,
                algorithms=["EdDSA"],
                audience=self.audience,
                issuer=self.issuer,
                leeway=LEEWAY_SECONDS,
                options={"require": REQUIRED_CLAIMS},
            )
        except jwt.PyJWTError as e:
            raise IdentityError(f"invalid identity token: {e}") from e
        return Identity(
            user_id=str(claims["sub"]),
            email=str(claims.get("email") or ""),
            groups=_str_list(claims.get("groups")),
            roles=_str_list(claims.get("roles")),
            mcp_tools=_str_list(claims.get("mcp_tools")),
            auth_method=str(claims.get("auth_method") or ""),
            source="jwt",
            claims=claims,
        )


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, str)]


def _pem_to_jwk(pem: str) -> dict:
    """Load a PKIX Ed25519 PEM as an OKP JWK so PyJWT pins the key type."""
    from base64 import urlsafe_b64encode

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("NETBIRD_PUBLIC_KEY_PEM is not an Ed25519 public key")
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    x = urlsafe_b64encode(raw).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x, "alg": "EdDSA"}
