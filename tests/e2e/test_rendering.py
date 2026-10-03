"""A JavaScript-rendered source on the live stack: the real headless Chromium, behind
its pinning egress proxy, renders a public page, and the pipeline stores what it
extracted. Needs internet access from the stack (CI runners have it).

The page is Zyte's scraping sandbox, made for exercising scrapers: its quotes exist
only once its script has run - the HTML has none - so records prove the browser ran
it. (IANA's example.com served until 2026-09, when its heading went: a page that
asks not to be relied on for testing.) The page must be public: sources reach
public addresses only (the SSRF guard), and the stack is not loosened for a test.

So the test depends on a site it does not control, and tells that site's troubles
from the platform's: a run that stores nothing is tried again, and if it still
stores nothing, the runner fetches the page itself. When the site serves this runner
no page, the test is skipped with the reason (the rendering path was not
exercised); when it does, the platform is at fault and the test fails, with every
run's statistics.
"""

from __future__ import annotations

import re
import time
from types import ModuleType
from typing import Any

import httpx2
import pytest

from tests.e2e.conftest import LiveStack, sign_up

API = "/api/v1"
PAGE = "https://quotes.toscrape.com/js/"  # ten quotes, written by the page's script
ATTEMPTS = 3  # a site may serve a CI runner something else for a while
PAUSE_SECONDS = 10


def _created(response: httpx2.Response) -> dict[str, Any]:
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


def _run(client: httpx2.Client, owner: dict[str, str], source_id: str) -> dict[str, Any]:
    """One collection run of the source, waited for."""
    queued = client.post(f"{API}/sources/{source_id}/runs", headers=owner)
    assert queued.status_code == 202, queued.text
    run_id = queued.json()["id"]
    deadline = time.monotonic() + 180
    while True:
        run: dict[str, Any] = client.get(f"{API}/runs/{run_id}", headers=owner).json()
        if run["status"] in ("succeeded", "failed", "cancelled"):
            return run
        if time.monotonic() > deadline:
            pytest.fail(f"the rendered run did not finish in time: {run}")
        time.sleep(2)


def _page_as_this_runner_gets_it() -> tuple[str | None, str]:
    """The page fetched directly (not through the stack, no JavaScript): why it is
    unavailable to this runner (None when it serves its page), and its HTML."""
    try:
        response = httpx2.get(PAGE, timeout=20, follow_redirects=True)
    except httpx2.HTTPError as error:
        return f"unreachable: {type(error).__name__}", ""
    if response.status_code != 200:
        return f"HTTP {response.status_code}", ""
    if "Quotes to Scrape" not in response.text or "var data" not in response.text:
        return "not the page it used to be", response.text
    return None, response.text


def test_a_javascript_source_is_rendered_by_the_real_browser(
    client: httpx2.Client, live: LiveStack, demo: ModuleType
) -> None:
    owner = sign_up(client, live, demo, "E2E Rendering")
    project = _created(client.post(f"{API}/projects", json={"name": "Rendered"}, headers=owner))
    dataset = _created(
        client.post(
            f"{API}/datasets",
            json={
                "project_id": project["id"],
                "name": "Quotes",
                "schema": {
                    "fields": [
                        {"name": "text", "type": "string", "required": True},
                        {"name": "author", "type": "string", "required": True},
                    ],
                    "key_field": "text",
                },
                "classification": "internal",
                "retention_days": 30,
            },
            headers=owner,
        )
    )
    source = _created(
        client.post(
            f"{API}/sources",
            json={
                "project_id": project["id"],
                "dataset_id": dataset["id"],
                "name": "Quotes, rendered",
                "config": {
                    "kind": "website",
                    "url": PAGE,
                    "item_selector": ".quote",
                    "fields": {"text": {"selector": ".text"}, "author": {"selector": ".author"}},
                    "render_javascript": True,
                },
            },
            headers=owner,
        )
    )

    outcomes: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    for attempt in range(ATTEMPTS):
        if attempt:
            time.sleep(PAUSE_SECONDS)
        run = _run(client, owner, source["id"])
        outcomes.append({k: run[k] for k in ("status", "error_code", "stats")})
        records = client.get(f"{API}/datasets/{dataset['id']}/records", headers=owner).json()[
            "items"
        ]
        if records:
            break
    else:
        unavailable, _ = _page_as_this_runner_gets_it()
        if unavailable is not None:
            pytest.skip(
                f"{PAGE} served this runner no page ({unavailable}): the rendering path "
                f"was not exercised. Runs: {outcomes}"
            )
        pytest.fail(f"{PAGE} serves its page, but the rendered runs stored nothing: {outcomes}")

    assert outcomes[-1]["status"] == "succeeded", outcomes
    assert len(records) >= 5, records
    assert all(record["data"]["text"] and record["data"]["author"] for record in records)
    assert "Albert Einstein" in {record["data"]["author"] for record in records}
    # What makes this a rendering test: without the script, the page has no quotes.
    _, html = _page_as_this_runner_gets_it()
    assert html, "the page could not be fetched to confirm it is rendered by its script"
    # `</script\b[^>]*>`: browsers also end a script at `</script >` or `</script foo>`.
    markup = re.sub(r"<script\b.*?</script\b[^>]*>", "", html, flags=re.DOTALL | re.IGNORECASE)
    assert not re.search(r"""class=["']quote["']""", markup), (
        "the page's HTML carries its quotes now: pick a page only JavaScript fills"
    )
