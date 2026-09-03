#!/usr/bin/env python3
"""
Bumps the patch component of version="X.Y.Z" in setup.py, in place, and
prints the new version to stdout (the release workflow captures this via
$GITHUB_OUTPUT).

Usage: python .github/scripts/bump_version.py
"""
import os
import re
import sys

SETUP_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "setup.py")

VERSION_RE = re.compile(r'(version\s*=\s*")(\d+)\.(\d+)\.(\d+)(")')


def bump():
    with open(SETUP_PY) as f:
        content = f.read()

    match = VERSION_RE.search(content)
    if not match:
        print('ERROR: could not find version="X.Y.Z" in setup.py', file=sys.stderr)
        sys.exit(1)

    prefix, major, minor, patch, suffix = match.groups()
    new_version = f"{major}.{minor}.{int(patch) + 1}"

    new_content = content[:match.start()] + f'{prefix}{new_version}{suffix}' + content[match.end():]
    with open(SETUP_PY, "w") as f:
        f.write(new_content)

    print(new_version)


if __name__ == "__main__":
    bump()
