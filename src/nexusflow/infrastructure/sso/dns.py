"""DNS TXT lookups over HTTPS (the JSON API of a DNS-over-HTTPS resolver).

Used to check domain-ownership records (``_nexusflow-verification.<domain>``).
The platform has no DNS library and its containers have no general DNS
egress; a DoH resolver (Cloudflare's by default, configurable) answers over
the same SSRF-safe HTTPS client as every other outbound request. The resolver
is trusted to report DNS truthfully - the residual risk of every DNS-based
domain verification (see docs/SSO.md).
"""

from __future__ import annotations

import re

from nexusflow.core.errors import NexusFlowError, TransientError
from nexusflow.infrastructure.http.client import SafeHttpClient
from nexusflow.infrastructure.sso.oidc import IdentityProviderUnavailableError

_TXT = 16
_MAX_RECORDS = 50
_MAX_RESPONSE_BYTES = 64 * 1024
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_JSON_TYPES = frozenset({"application/dns-json", "application/json"})


def _txt_value(data: str) -> str:
    """A TXT record as one string: its quoted character-strings joined
    (RFC 7208, section 3.3); unquoted data is taken as it is."""
    parts = _QUOTED.findall(data)
    if not parts:
        return data.strip()
    return "".join(part.replace('\\"', '"').replace("\\\\", "\\") for part in parts)


class DohTxtResolver:
    """Implements :class:`nexusflow.domain.identity.sso.TxtResolver`."""

    def __init__(self, http: SafeHttpClient, *, resolver_url: str) -> None:
        self._http = http
        self._resolver_url = resolver_url

    async def txt_records(self, name: str) -> list[str]:
        try:
            response = await self._http.request(
                "GET",
                self._resolver_url,
                params={"name": name, "type": "TXT"},
                headers={"Accept": "application/dns-json"},
                max_bytes=_MAX_RESPONSE_BYTES,
                follow_redirects=False,
                raise_for_status=False,
            )
        except TransientError as exc:
            raise IdentityProviderUnavailableError(
                "The DNS resolver is not reachable. Try again later.", internal_detail=exc.code
            ) from exc
        if response.status_code != 200 or response.content_type not in _JSON_TYPES:
            raise IdentityProviderUnavailableError(
                "The DNS resolver did not answer. Try again later.",
                internal_detail=f"HTTP {response.status_code} {response.content_type}",
            )
        try:
            document = response.json(max_depth=8)
        except NexusFlowError as exc:  # malformed or too deep: no usable answer
            raise IdentityProviderUnavailableError(
                internal_detail="resolver answer not JSON"
            ) from exc
        if not isinstance(document, dict):
            return []
        answers = document.get("Answer")
        if document.get("Status") != 0 or not isinstance(answers, list):
            return []  # NXDOMAIN, SERVFAIL, no records: nothing proves anything
        return [
            _txt_value(str(answer["data"]))
            for answer in answers[:_MAX_RECORDS]
            if isinstance(answer, dict)
            and answer.get("type") == _TXT
            and isinstance(answer.get("data"), str)
        ]
