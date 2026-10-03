#!/usr/bin/env python3
"""Sanitize build diagnostics; record dependency output identities on failure."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys


def sanitize(value):
    for key, secret in sorted(os.environ.items(), key=lambda entry: len(entry[1]), reverse=True):
        if secret and (re.search(r'TOKEN|PASSWORD|SECRET|PRIVATE_KEY|SIGNING_KEY|API_KEY|ACCESS_KEY|CREDENTIAL', key, re.I) or key in ('HOME', 'LOOMEX_BUILD_TEMP')):
            value = value.replace(secret, '<redacted:' + key + '>')
    value = re.sub(r'(?i)(["\'](?:accessToken|refreshToken|token|password|secret|api[_-]?key)["\']\s*:\s*["\'])[^"\']+', r'\1<redacted>', value)
    value = re.sub(r'(?i)(authorization\s*[:=]\s*|bearer\s+)[^\s,;]+', r'\1<redacted>', value)
    value = re.sub(r'(?i)((?:token|password|secret|api[_-]?key)\s*[:=]\s*)[^\s,;]+', r'\1<redacted>', value)
    return value


def main():
    mode = sys.argv[1]
    if mode == 'log':
        with open(sys.argv[2], 'a', encoding='utf-8') as log:
            for line in sys.stdin:
                clean = sanitize(line)
                log.write(clean)
                sys.stdout.write(clean)
        return
    if mode == 'record':
        root = Path(sys.argv[2])
        invocation = [sanitize(arg) for arg in sys.argv[3:]]
        with (root / 'invocations.jsonl').open('a') as output:
            output.write(json.dumps({'cwd': '<build-source>', 'argv': invocation,
                                    'rustflags': sanitize(os.environ.get('RUSTFLAGS', '')),
                                    'cflags': sanitize(os.environ.get('CFLAGS', ''))}) + '\n')
        return
    if mode == 'failure':
        root = Path(sys.argv[2])
        outputs = []
        for path in sorted((root / 'target').rglob('*')):
            if not path.is_file() or path.is_symlink() or 'build' not in path.relative_to(root).parts:
                continue
            digest = hashlib.sha256()
            with path.open('rb') as file:
                for block in iter(lambda: file.read(65536), b''):
                    digest.update(block)
            outputs.append({'path': str(path.relative_to(root)), 'sha256': digest.hexdigest(), 'size': path.stat().st_size})
        (root / 'failure-evidence.json').write_text(json.dumps({'schema': 'loomex.build-failure/v1',
            'exitCode': int(sys.argv[3]), 'dependencyOutputs': outputs,
            'scope': 'private source snapshot and compiler outputs; logs and invocation metadata sanitized'}, indent=2) + '\n')
        return
    raise SystemExit('unsupported mode')


if __name__ == '__main__':
    main()
