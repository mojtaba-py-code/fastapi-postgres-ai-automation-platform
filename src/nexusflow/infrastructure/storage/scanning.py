"""Malware scanning of uploads via ClamAV's ``clamd`` INSTREAM protocol."""

from __future__ import annotations

import asyncio
import struct
from pathlib import Path

from nexusflow.core.errors import ServiceUnavailableError
from nexusflow.domain.shared.ports import ScanVerdict

_CHUNK = 64 * 1024


class NoopScanner:
    """Used when no scanner is configured (reported as a security warning at start-up)."""

    async def scan(self, path: Path) -> ScanVerdict:
        return ScanVerdict(clean=True)


class ClamdScanner:
    def __init__(self, host: str, port: int, *, timeout_seconds: float = 30.0) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout_seconds

    @classmethod
    def from_address(cls, address: str) -> ClamdScanner:
        host, _, port = address.rpartition(":")
        return cls(host or "clamav", int(port or 3310))

    async def scan(self, path: Path) -> ScanVerdict:
        try:
            async with asyncio.timeout(self._timeout):
                reader, writer = await asyncio.open_connection(self._host, self._port)
                try:
                    writer.write(b"zINSTREAM\0")
                    handle = await asyncio.to_thread(path.open, "rb")
                    try:
                        while chunk := await asyncio.to_thread(handle.read, _CHUNK):
                            writer.write(struct.pack("!L", len(chunk)) + chunk)
                            await writer.drain()
                    finally:
                        await asyncio.to_thread(handle.close)
                    writer.write(struct.pack("!L", 0))
                    await writer.drain()
                    response = (await reader.read(4096)).decode("utf-8", "replace").strip("\0 \n")
                finally:
                    writer.close()
                    await writer.wait_closed()
        except (OSError, TimeoutError) as exc:
            # Fail closed: an unscanned file is not accepted.
            raise ServiceUnavailableError(internal_detail=f"clamd unavailable: {exc}") from exc
        if response.endswith("OK"):
            return ScanVerdict(clean=True)
        if "FOUND" in response:
            signature = response.rsplit(":", 1)[-1].replace("FOUND", "").strip()[:100]
            return ScanVerdict(clean=False, signature=signature)
        raise ServiceUnavailableError(
            internal_detail=f"unexpected clamd response: {response[:100]}"
        )
