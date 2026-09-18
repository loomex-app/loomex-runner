#!/usr/bin/env python3
"""Fail before signing a runner that cannot connect to its configured service."""
import os
import ipaddress
import re
from urllib.parse import urlsplit


def valid_origin(value):
    try:
        url = urlsplit(value)
        host = url.hostname or ''
        try:
            ipaddress.ip_address(host)
            valid_host = True
        except ValueError:
            ascii_host = host.encode('idna').decode('ascii').rstrip('.')
            valid_host = len(ascii_host) <= 253 and all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label) for label in ascii_host.split('.'))
        return bool(value and url.scheme == 'https' and url.hostname
                    and url.username is None and url.password is None and valid_host
                    and not url.query and not url.fragment
                    and url.path in ('', '/') and '?' not in value and '#' not in value
                    and not any(c.isspace() for c in value)
                    and (url.port is None or 0 < url.port <= 65535))
    except (ValueError, UnicodeError):
        return False


def main():
    for name in ('LOOMEX_API_ORIGIN', 'LOOMEX_WEB_APP_ORIGIN'):
        if not valid_origin(os.environ.get(name, '')):
            raise SystemExit(f'{name} must be a configured HTTPS origin without credentials, path, query or fragment')


if __name__ == '__main__':
    main()
