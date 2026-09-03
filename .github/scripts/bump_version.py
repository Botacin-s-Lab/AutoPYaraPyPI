#!/usr/bin/env python3
"""
Bumps version="X.Y.Z" in setup.py, in place, and prints the new version to
stdout (the release workflow captures this via $GITHUB_OUTPUT).

Usage: python .github/scripts/bump_version.py <patch|minor>
  patch: 0.1.5 -> 0.1.6   (triggered by "New subversion" in the commit subject)
  minor: 0.1.5 -> 0.2.0   (triggered by "New version" in the commit subject;
                           resets patch to 0, per normal semver convention)
"""
import os
import re
import sys

SETUP_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "setup.py")

VERSION_RE = re.compile(r'(version\s*=\s*")(\d+)\.(\d+)\.(\d+)(")')


def bump(kind):
    with open(SETUP_PY) as f:
        content = f.read()

    match = VERSION_RE.search(content)
    if not match:
        print('ERROR: could not find version="X.Y.Z" in setup.py', file=sys.stderr)
        sys.exit(1)

    prefix, major, minor, patch, suffix = match.groups()
    major, minor, patch = int(major), int(minor), int(patch)

    if kind == "patch":
        patch += 1
    elif kind == "minor":
        minor += 1
        patch = 0
    else:
        print(f'ERROR: unknown bump kind {kind!r}, expected "patch" or "minor"', file=sys.stderr)
        sys.exit(1)

    new_version = f"{major}.{minor}.{patch}"

    new_content = content[:match.start()] + f'{prefix}{new_version}{suffix}' + content[match.end():]
    with open(SETUP_PY, "w") as f:
        f.write(new_content)

    print(new_version)


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("patch", "minor"):
        print('Usage: bump_version.py <patch|minor>', file=sys.stderr)
        sys.exit(1)
    bump(sys.argv[1])
