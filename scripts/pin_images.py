"""Pin every container image the platform builds from or runs to a digest.

A tag can be moved to different content; a digest cannot. This script finds
image references in the Dockerfiles (``FROM repo:tag`` and the ``# syntax=``
frontend), the Compose files (``image: ${NAME_IMAGE:-repo:tag}``) and the CI
workflows (``image: repo:tag``), asks each registry for the digest the tag
points at today (the multi-platform index, so every architecture stays
pinned), and writes it next to the tag, which stays for readability:

    python scripts/pin_images.py            # resolve and write the digests
    python scripts/pin_images.py --check    # exit 1 if a reference has no digest (CI)
    python scripts/pin_images.py --list     # the third-party images that run, one per line

Those are the forms Dependabot reads - it proposes tag updates (run this
script again afterwards, ``make pin-images``). A deployment overrides one
image with its variable, digest included:
``NGINX_IMAGE=nginxinc/nginx-unprivileged:1.30-alpine@sha256:...``.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    "docker/Dockerfile",
    "docker/Dockerfile.browser",
    "docker-compose.yml",
    "docker-compose.dev.yml",
    "docker-compose.demo.yml",
    ".github/workflows/ci.yml",
)

_DIGEST = r"sha256:[0-9a-f]{64}"
_REPO = r"[a-z0-9][a-z0-9._/-]*"
_TAG = r"[A-Za-z0-9_][A-Za-z0-9._-]{0,127}"
# FROM python:3.12-slim-bookworm[@sha256:...] [AS stage]
_FROM = re.compile(
    rf"^(?P<head>FROM\s+)(?P<repo>{_REPO}):(?P<tag>{_TAG})(?:@(?P<digest>{_DIGEST}))?"
    rf"(?P<tail>(?:\s+[Aa][Ss]\s+[\w.-]+)?\s*)$"
)
# # syntax=docker/dockerfile:1.7[@sha256:...]   (the BuildKit frontend)
_SYNTAX = re.compile(
    rf"^(?P<head>#\s*syntax=)(?P<repo>{_REPO}):(?P<tag>{_TAG})(?:@(?P<digest>{_DIGEST}))?\s*$"
)
# image: ${POSTGRES_IMAGE:-postgres:17-alpine[@sha256:...]}
_COMPOSE = re.compile(
    rf"^(?P<head>\s*image:\s*\$\{{(?P<var>\w+):-)(?P<repo>{_REPO}):(?P<tag>{_TAG})"
    rf"(?:@(?P<digest>{_DIGEST}))?(?P<tail>\}}.*)$"
)
# The platform's own images, built from this repository: never pinned.
LOCAL_IMAGES = frozenset({"nexusflow-ai", "nexusflow-browser"})
# image: postgres:17-alpine[@sha256:...]   (CI service containers)
_LITERAL = re.compile(
    rf"^(?P<head>\s*image:\s*)(?P<repo>{_REPO}):(?P<tag>{_TAG})(?:@(?P<digest>{_DIGEST}))?(?P<tail>\s*(?:#.*)?)$"
)
_ACCEPT = ", ".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
)


@dataclass(frozen=True, slots=True)
class Reference:
    path: str
    line: int
    repo: str
    tag: str
    digest: str | None


type Resolver = Callable[[str, str], str]


def _match(line: str) -> re.Match[str] | None:
    for pattern in (_FROM, _SYNTAX, _COMPOSE, _LITERAL):
        match = pattern.match(line)
        if match and "${" not in match["repo"] and match["repo"] not in LOCAL_IMAGES:
            return match
    return None


def scan(text: str, path: str) -> list[Reference]:
    """Image references in one file, in order."""
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        match = _match(line)
        if match:
            found.append(Reference(path, number, match["repo"], match["tag"], match["digest"]))
    return found


def pin(text: str, resolve: Resolver) -> str:
    """``text`` with every reference's digest set to what its tag points at now."""
    lines = []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        ending = line[len(body) :]
        match = _match(body)
        if match is not None:
            digest = resolve(match["repo"], match["tag"])
            start, end = match.span("tag")
            if match["digest"] is not None:
                end = match.end("digest")
            body = f"{body[:start]}{match['tag']}@{digest}{body[end:]}"
        lines.append(body + ending)
    return "".join(lines)


# ---------------------------------------------------------------- registries


def _registry(repo: str) -> tuple[str, str]:
    """(registry host, repository path) for an image name, Docker Hub by default."""
    first, _, rest = repo.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        return first, rest
    return "registry-1.docker.io", repo if rest else f"library/{repo}"


def registry_digest(repo: str, tag: str) -> str:
    """The digest ``repo:tag`` points at, asked of its registry (anonymous pull)."""
    import httpx2  # noqa: PLC0415 - only for asking registries: --check and --list need no deps

    host, path = _registry(repo)
    url = f"https://{host}/v2/{path}/manifests/{tag}"
    headers = {"Accept": _ACCEPT}
    with httpx2.Client(timeout=30.0, follow_redirects=True) as client:
        response = client.head(url, headers=headers)
        if response.status_code == 401:
            headers["Authorization"] = f"Bearer {_token(client, response, path)}"
            response = client.head(url, headers=headers)
        response.raise_for_status()
        digest = response.headers.get("docker-content-digest", "")
    if not re.fullmatch(_DIGEST, digest):
        raise RuntimeError(f"{repo}:{tag}: the registry returned no digest")
    return digest


def _token(client: Any, challenge: Any, path: str) -> str:
    """An anonymous pull token, from the realm the registry's challenge names."""
    header = challenge.headers.get("www-authenticate", "")
    fields = dict(re.findall(r'(\w+)="([^"]*)"', header))
    if "realm" not in fields:
        raise RuntimeError(f"unexpected authentication challenge: {header!r}")
    params = {"scope": fields.get("scope", f"repository:{path}:pull")}
    if "service" in fields:
        params["service"] = fields["service"]
    response = client.get(fields["realm"], params=params)
    response.raise_for_status()
    body = response.json()
    return str(body.get("token") or body["access_token"])


# ---------------------------------------------------------------- command line


def _files() -> Iterable[Path]:
    return (ROOT / name for name in FILES if (ROOT / name).exists())


def runtime_images() -> list[str]:
    """The pinned third-party images the stack runs as they are (Compose files,
    CI services), for the weekly scan. Base images are left out: what runs is
    the image built from them - which CI scans on every change and every week -
    after the build removed what it does not need."""
    return sorted(
        {
            f"{ref.repo}:{ref.tag}@{ref.digest}"
            for path in _files()
            if not path.name.startswith("Dockerfile")
            for ref in scan(path.read_text(encoding="utf-8"), path.name)
            if ref.digest is not None
        }
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if a reference has no digest")
    parser.add_argument(
        "--list", action="store_true", help="print the third-party images that run, once each"
    )
    args = parser.parse_args(argv)
    if args.list:
        print("\n".join(runtime_images()))
        return 0
    if args.check:
        unpinned = [
            ref
            for path in _files()
            for ref in scan(path.read_text(encoding="utf-8"), path.relative_to(ROOT).as_posix())
            if ref.digest is None
        ]
        for ref in unpinned:
            print(f"{ref.path}:{ref.line}: {ref.repo}:{ref.tag} is not pinned to a digest")
        if unpinned:
            print("Run: python scripts/pin_images.py", file=sys.stderr)
        return 1 if unpinned else 0

    cache: dict[tuple[str, str], str] = {}

    def resolve(repo: str, tag: str) -> str:
        if (repo, tag) not in cache:
            cache[(repo, tag)] = registry_digest(repo, tag)
            print(f"{repo}:{tag} -> {cache[(repo, tag)]}")
        return cache[(repo, tag)]

    for path in _files():
        text = path.read_text(encoding="utf-8")
        pinned = pin(text, resolve)
        if pinned != text:
            path.write_text(pinned, encoding="utf-8", newline="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
