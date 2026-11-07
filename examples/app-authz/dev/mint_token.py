#!/usr/bin/env python3
"""Mint NetBird-style identity JWTs with a local test key.

Examples:
  python dev/mint_token.py pem                       # public key for your app
  python dev/mint_token.py jwks                      # same key as a JWKS
  python dev/mint_token.py token --preset viewer --domain tickets.localhost
  python dev/mint_token.py token --sub usr_1 --email me@example.com \\
      --roles admin --tools '*' --domain whoami.localhost
  python dev/mint_token.py token --preset admin --ttl -30   # already expired

The first run creates dev/keys/signing-key.pem (gitignored).
"""

import argparse
import sys

import devkeys


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("pem", help="print the public key as PEM (NETBIRD_PUBLIC_KEY_PEM)")
    sub.add_parser("jwks", help="print the public key as a JWKS document")

    tok = sub.add_parser("token", help="print a signed identity token")
    tok.add_argument("--domain", required=True, help="service domain, used for iss and aud")
    tok.add_argument("--preset", choices=sorted(devkeys.PRESETS), help="start from an example identity")
    tok.add_argument("--sub", help="user id (sub)")
    tok.add_argument("--email")
    tok.add_argument("--groups", type=_csv, help="comma-separated group names")
    tok.add_argument("--roles", type=_csv, help="comma-separated roles")
    tok.add_argument("--tools", type=_csv, help="comma-separated MCP tool globs, e.g. 'list_*,get_ticket'")
    tok.add_argument("--auth-method", choices=["oidc", "header", "password", "pin"])
    tok.add_argument("--ttl", type=int, default=60, help="lifetime in seconds; <= 0 mints an expired token")
    tok.add_argument("--issuer", help="override iss (default https://<domain>)")

    args = parser.parse_args()
    key = devkeys.load_or_create_key()

    if args.cmd == "pem":
        sys.stdout.write(devkeys.public_pem(key))
        return 0
    if args.cmd == "jwks":
        print(devkeys.jwks_json(key))
        return 0

    ident = dict(devkeys.PRESETS.get(args.preset or "", {}))
    for field, value in (
        ("sub", args.sub),
        ("email", args.email),
        ("groups", args.groups),
        ("roles", args.roles),
        ("mcp_tools", args.tools),
        ("auth_method", args.auth_method),
    ):
        if value is not None:
            ident[field] = value
    if not ident.get("sub"):
        parser.error("set --sub or --preset")

    print(devkeys.mint(key, args.domain, ttl=args.ttl, issuer=args.issuer, **ident))
    return 0


if __name__ == "__main__":
    sys.exit(main())
