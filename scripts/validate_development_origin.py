#!/usr/bin/env python3
"""Validate and canonicalize the debug runner's loopback API origin."""

from __future__ import annotations

import argparse
import ipaddress
from urllib.parse import urlsplit, urlunsplit


def canonical_origin(raw: str) -> str:
    if raw != raw.strip() or any(character in raw for character in "\r\n\t?#%"):
        raise ValueError("development API origin contains forbidden syntax")
    parsed = urlsplit(raw)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("development API origin must be a root loopback HTTP(S) URL")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("development API origin has an invalid port") from error
    hostname = parsed.hostname.lower()
    if hostname != "localhost":
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError as error:
            raise ValueError("development API origin host is not loopback") from error
        if not address.is_loopback:
            raise ValueError("development API origin host is not loopback")
        hostname = f"[{address.compressed}]" if address.version == 6 else address.compressed
    netloc = hostname if port is None else f"{hostname}:{port}"
    return urlunsplit((parsed.scheme, netloc, "/", "", ""))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("origin")
    args = parser.parse_args()
    try:
        print(canonical_origin(args.origin))
    except ValueError as error:
        raise SystemExit(f"invalid development API origin: {error}") from error


if __name__ == "__main__":
    main()
