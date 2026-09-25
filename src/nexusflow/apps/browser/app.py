"""Isolated headless-browser rendering service (its own container and network).

    uvicorn nexusflow.apps.browser.app:create_browser_app --factory --port 8090

``POST /render {"url": ...}`` -> ``{"html": ..., "final_url": ...}`` for pages
that need JavaScript. Only the sandbox pool can reach it, and only with the
shared bearer token. Defences, from outside in:

* container: non-root, read-only root filesystem, no capabilities, memory and
  PID limits, an egress network without inter-container traffic (the host
  firewall rules in DEPLOYMENT.md additionally drop private ranges);
* request: the target passes the same static URL policy as every other fetch;
* network: Chromium can only connect through the in-process pinning proxy
  (:mod:`.egress_proxy`), which resolves every host itself, requires public
  addresses and connects to exactly the address it checked - DNS rebinding
  between check and connect is impossible; QUIC and non-proxied WebRTC UDP
  are disabled so nothing bypasses the proxy;
* every browser request (documents, redirects, scripts, XHR, images...) is
  also intercepted early: non-HTTP(S) schemes and non-public hosts are
  aborted before Chromium even asks the proxy; the final URL is re-checked;
* page: fresh incognito context per render, destroyed afterwards; downloads,
  service workers, WebSockets, permissions and dialogs are disabled;
* limits: bounded concurrency with a queue timeout, a deadline on the whole
  visit (navigation timeout plus a margin to read the page) and a cap on the
  returned HTML.
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from nexusflow.apps.browser.egress_proxy import PinningProxy
from nexusflow.bootstrap.http import build_url_policy
from nexusflow.core.config import BrowserServiceSettings
from nexusflow.core.errors import PolicyViolationError
from nexusflow.domain.shared.url_policy import UrlPolicy, forbidden_ip_reason
from nexusflow.infrastructure.observability.logging import configure_logging, get_logger

_log = get_logger("nexusflow.browser")
_ABORT_REASON = "blockedbyclient"
_CONTENT_MARGIN_SECONDS = 10.0  # after the navigation timeout, to read the loaded page
_CLOSE_TIMEOUT_SECONDS = 10.0


class RenderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str = Field(min_length=10, max_length=2048)


class RenderResponse(BaseModel):
    html: str
    final_url: str


async def resolves_publicly(host: str) -> bool:
    """True only if *every* address the host resolves to is public."""
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None:
        return forbidden_ip_reason(literal) is None
    try:
        answers = await asyncio.get_running_loop().getaddrinfo(host, None)
    except OSError:
        return False
    addresses = {ipaddress.ip_address(str(answer[4][0]).split("%", 1)[0]) for answer in answers}
    return bool(addresses) and all(forbidden_ip_reason(a) is None for a in addresses)


class Renderer:
    def __init__(self, settings: BrowserServiceSettings, policy: UrlPolicy) -> None:
        self._settings = settings
        self._policy = policy
        self._slots = asyncio.Semaphore(settings.browser.max_concurrency)
        self._proxy = PinningProxy(policy)
        self._playwright: Any = None
        self._browser: Any = None

    async def start(self) -> None:
        from playwright.async_api import async_playwright  # noqa: PLC0415 - optional extra

        proxy_port = await self._proxy.start()
        self._playwright = await async_playwright().start()
        args = [
            "--disable-dev-shm-usage",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-default-apps",
            "--no-first-run",
            "--mute-audio",
            # Nothing may bypass the pinning proxy: no QUIC, no direct WebRTC UDP.
            "--disable-quic",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            "--dns-prefetch-disable",
        ]
        # Without Chromium's sandbox (it needs user namespaces), the hardened
        # container is the isolation boundary - see docs/DEPLOYMENT.md.
        self._browser = await self._playwright.chromium.launch(
            args=args,
            chromium_sandbox=self._settings.browser.chromium_sandbox,
            # "<-loopback>" removes Chromium's implicit proxy bypass for localhost.
            proxy={"server": f"http://127.0.0.1:{proxy_port}", "bypass": "<-loopback>"},
        )

    async def stop(self) -> None:
        if self._browser is not None:
            await self._browser.close()
        if self._playwright is not None:
            await self._playwright.stop()
        await self._proxy.stop()

    async def _guard(self, route: Any) -> None:
        try:
            target = self._policy.validate(route.request.url)
        except PolicyViolationError:
            await route.abort(_ABORT_REASON)
            return
        if not await resolves_publicly(target.host):
            await route.abort(_ABORT_REASON)
            return
        await route.continue_()

    async def render(self, url: str) -> RenderResponse:
        browser_settings = self._settings.browser
        target = self._policy.validate(url)
        try:
            await asyncio.wait_for(self._slots.acquire(), browser_settings.queue_timeout_seconds)
        except TimeoutError as exc:
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Renderer busy.") from exc
        context = None
        try:
            context = await self._browser.new_context(
                accept_downloads=False,
                service_workers="block",
                ignore_https_errors=False,
                java_script_enabled=True,
                permissions=[],
                user_agent=self._settings.scraping.user_agent,
            )
            await context.route("**/*", self._guard)
            await context.route_web_socket("**/*", lambda socket: socket.close())
            page = await context.new_page()
            page.on("dialog", lambda dialog: asyncio.ensure_future(dialog.dismiss()))
            page.on("popup", lambda popup: asyncio.ensure_future(popup.close()))
            # A page can keep its renderer busy once loaded (an endless script):
            # content() would then never return and the slot be lost for good.
            # The whole visit has a deadline; the context is closed either way.
            deadline = browser_settings.navigation_timeout_seconds + _CONTENT_MARGIN_SECONDS
            async with asyncio.timeout(deadline):
                await page.goto(
                    target.url,
                    wait_until="load",
                    timeout=browser_settings.navigation_timeout_seconds * 1000,
                )
                final = self._policy.validate(page.url)
                if not await resolves_publicly(final.host):
                    raise PolicyViolationError(code="blocked_redirect")
                html = await page.content()
            if len(html.encode("utf-8")) > browser_settings.max_html_bytes:
                raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Page too large.")
            return RenderResponse(html=html, final_url=final.url)
        finally:
            try:
                if context is not None:
                    await _close(context)
            finally:
                self._slots.release()


async def _close(context: Any) -> None:
    """Destroy a render's context; one that will not close cannot keep the slot."""
    try:
        async with asyncio.timeout(_CLOSE_TIMEOUT_SECONDS):
            await context.close()
    except Exception as exc:  # noqa: BLE001 - logged; the render's own outcome stands
        _log.warning("render_close_failed", error=type(exc).__name__)


def create_browser_app(settings: BrowserServiceSettings | None = None) -> FastAPI:
    settings = settings or BrowserServiceSettings()
    configure_logging(
        level=settings.observability.log_level,
        fmt=settings.observability.log_format,
        service="nexusflow-browser",
    )
    renderer = Renderer(settings, build_url_policy(settings.scraping))
    token = settings.browser.token.get_secret_value() if settings.browser.token else ""

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await renderer.start()
        try:
            yield
        finally:
            await renderer.stop()

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    def authorized(authorization: Annotated[str | None, Header()] = None) -> None:
        presented = (authorization or "").removeprefix("Bearer ").strip()
        if not token or not hmac.compare_digest(presented.encode(), token.encode()):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unauthorized.")

    @app.get("/health/live")
    async def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/render", response_model=RenderResponse, dependencies=[Depends(authorized)])
    async def render(body: RenderRequest) -> RenderResponse:
        try:
            return await renderer.render(body.url)
        except PolicyViolationError as exc:
            _log.info("render_blocked", code=exc.code)
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "URL not allowed.") from exc
        except HTTPException:
            raise
        except Exception as exc:
            _log.warning("render_failed", error=type(exc).__name__)
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Render failed.") from exc

    return app
