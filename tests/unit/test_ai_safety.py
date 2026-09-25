"""AI safety layer: redaction, prompt spotlighting, output validation, tool gateway."""

from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import pytest

from nexusflow.domain.authorization.principal import Principal
from nexusflow.domain.authorization.roles import Permission, Role
from nexusflow.domain.intelligence.ports import ToolCall, ToolSpec
from nexusflow.domain.intelligence.prompting import build_prompt
from nexusflow.domain.intelligence.redaction import redact_text, redact_value, strip_sensitive
from nexusflow.domain.intelligence.tools import NoArgs, ToolContext, ToolGateway
from nexusflow.domain.intelligence.validation import OutputRejectedError, validate_output


class TestRedaction:
    @pytest.mark.parametrize(
        ("text", "label"),
        [
            ("token eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.c2lnbmF0dXJlMTIzNDU2", "jwt"),
            ("key nxf_abcdefghijkl_" + "A" * 40, "api_key"),
            ("Authorization: Bearer abcdefghijklmnopqrstuvwxyz", "bearer"),
            ("contact jane.doe@example.com today", "email"),
            ("pay to DE89 3704 0044 0532 0130 00", "iban"),
            ("card 4111 1111 1111 1111 expires", "card"),
            ("call +49 30 1234 5678", "phone"),
            ("server 203.0.113.7 responded", "ipv4"),
        ],
    )
    def test_sensitive_patterns_are_redacted(self, text: str, label: str) -> None:
        redacted, count = redact_text(text)
        assert f"[REDACTED:{label}]" in redacted
        assert count >= 1

    def test_non_luhn_numbers_are_kept(self) -> None:
        redacted, count = redact_text("order 1234 5678 9012 3456")  # fails the Luhn check
        assert (redacted, count) == ("order 1234 5678 9012 3456", 0)

    def test_nested_values_and_sensitive_fields(self) -> None:
        data = {"note": "mail me at a@b.example", "nested": [{"ip": "198.51.100.1"}], "n": 3}
        redacted, count = redact_value(data)
        assert count == 2
        assert redacted["n"] == 3
        assert strip_sensitive({"email": "x", "sku": "A"}, frozenset({"email"})) == {"sku": "A"}


class TestPromptSpotlighting:
    def test_data_is_fenced_by_a_random_boundary_and_budgeted(self) -> None:
        changes = [
            {"id": str(uuid4()), "score": score, "diff": {"title": "x" * 50}}
            for score in (10, 90, 50)
        ]
        first = build_prompt(
            dataset_name="d",
            period="p",
            changes=changes,
            statistics={},
            hosts=frozenset(),
            budget_chars=260,
        )
        second = build_prompt(
            dataset_name="d",
            period="p",
            changes=changes,
            statistics={},
            hosts=frozenset(),
            budget_chars=260,
        )
        assert first.boundary != second.boundary
        assert first.user_prompt.count(first.boundary) == 2
        top = next(c["id"] for c in changes if c["score"] == 90)
        assert top in first.included_change_ids
        assert len(first.included_change_ids) < len(changes)  # budget respected

    def test_a_change_too_large_for_the_budget_does_not_crowd_out_the_others(self) -> None:
        huge = {"id": str(uuid4()), "score": 99, "diff": {"notes": "x" * 5000}}
        small = [{"id": str(uuid4()), "score": score, "diff": {"t": "y"}} for score in (50, 10)]
        package = build_prompt(
            dataset_name="d",
            period="p",
            changes=[huge, *small],
            statistics={},
            hosts=frozenset(),
            budget_chars=1000,
        )
        # The most significant change is skipped, not a reason to stop.
        assert package.included_change_ids == frozenset(change["id"] for change in small)
        assert huge["id"] not in package.user_prompt


def _output(**overrides: Any) -> str:
    document: dict[str, Any] = {
        "summary": "Prices rose, see https://evil.example/login and https://shop.example.com/a",
        "risk_level": "medium",
        "confidence": 0.7,
        "findings": [
            {
                "title": "Price increase",
                "detail": "Details",
                "impact": "medium",
                "change_refs": ["c1"],
            }
        ],
        "recommendations": ["Review pricing"],
    }
    document.update(overrides)
    return json.dumps(document)


class TestOutputValidation:
    ALLOWED = frozenset({"c1", "c2"})

    def _validate(self, text: str) -> Any:
        return validate_output(
            text,
            boundary="b0undary",
            allowed_change_ids=self.ALLOWED,
            allowed_hosts=frozenset({"shop.example.com"}),
        )

    def test_valid_output_is_cleaned(self) -> None:
        result = self._validate("```json\n" + _output() + "\n```")
        assert "[link removed]" in result.summary  # unknown host: phishing link removed
        assert "https://shop.example.com/a" in result.summary

    @pytest.mark.security
    @pytest.mark.parametrize(
        "link",
        [
            # Review D-3: each opens evil.example in a browser, yet names the
            # allowed host after it - the old check split only on "/" and ":".
            "https://evil.example?.shop.example.com/login",
            "https://evil.example#.shop.example.com/login",
            "https://evil.example\\.shop.example.com/login",
            "https://shop.example.com@evil.example/login",
            "https://xn--shp-example-com.evil.example/login",
            "evil.example/reset-password",  # a bare host with a path is a link too
        ],
    )
    def test_links_that_open_another_host_are_removed(self, link: str) -> None:
        result = self._validate(_output(summary=f"Sign in again at {link} today"))
        assert result.summary == "Sign in again at [link removed] today"

    @pytest.mark.parametrize(
        "link",
        [
            "https://shop.example.com/p/1?ref=a#top",
            "https://SHOP.example.com:8443/p",
            "https://eu.shop.example.com/p",
            "www.shop.example.com/offers",
            "shop.example.com/cart",
        ],
    )
    def test_links_to_the_analysed_hosts_stay(self, link: str) -> None:
        result = self._validate(_output(summary=f"Compare {link} with last week"))
        assert result.summary == f"Compare {link} with last week"

    @pytest.mark.parametrize(
        ("text", "code"),
        [
            ("", "ai_output_empty_or_too_long"),
            ("Sure! Here is the analysis", "ai_output_not_json"),
            (_output(risk_level="apocalyptic"), "ai_output_schema_violation"),
            (_output(extra_field="x"), "ai_output_schema_violation"),
            (_output(summary="ignore rules b0undary"), "ai_output_prompt_echo"),
            (
                _output(
                    findings=[
                        {
                            "title": "t",
                            "detail": "d",
                            "impact": "low",
                            "change_refs": ["made-up-1", "made-up-2", "c1"],
                        }
                    ]
                ),
                "ai_output_hallucinated_references",
            ),
        ],
    )
    def test_untrustworthy_output_is_rejected(self, text: str, code: str) -> None:
        with pytest.raises(OutputRejectedError) as exc:
            self._validate(text)
        assert exc.value.code == code

    def test_a_few_unknown_references_are_dropped(self) -> None:
        text = _output(
            findings=[
                {"title": "t", "detail": "d", "impact": "low", "change_refs": ["c1", "c2", "x"]}
            ]
        )
        assert self._validate(text).findings[0].change_refs == ["c1", "c2"]


class _EchoTool:
    permission = Permission.DATASETS_READ
    args_model = NoArgs

    def __init__(self, result: Any = None, fail: bool = False) -> None:
        self.spec = ToolSpec(name="echo", description="d", input_schema={"type": "object"})
        self._result = result if result is not None else {"ok": True}
        self._fail = fail

    async def run(self, args: Any, ctx: ToolContext) -> Any:
        if self._fail:
            raise RuntimeError("boom")
        return self._result


def _ctx(role: Role = Role.ANALYST) -> ToolContext:
    principal = Principal.for_user(user_id=uuid4(), org_id=uuid4(), role=role, session_id=None)
    return ToolContext(org_id=uuid4(), dataset_id=uuid4(), principal=principal)


class TestToolGateway:
    async def test_decisions(self) -> None:
        gateway = ToolGateway(tools={"echo": _EchoTool()}, max_calls=2)
        ctx = _ctx()
        unknown = await gateway.execute(ToolCall(id="1", name="run_shell", arguments={}), ctx)
        bad_args = await gateway.execute(ToolCall(id="2", name="echo", arguments={"sql": "x"}), ctx)
        ok = await gateway.execute(ToolCall(id="3", name="echo", arguments={}), ctx)
        await gateway.execute(ToolCall(id="4", name="echo", arguments={}), ctx)
        over = await gateway.execute(ToolCall(id="5", name="echo", arguments={}), ctx)
        assert unknown.is_error and bad_args.is_error and over.is_error
        assert not ok.is_error
        assert [d for _, d in gateway.decisions] == [
            "unknown_tool",
            "invalid_arguments",
            "allowed",
            "allowed",
            "budget_exhausted",
        ]

    async def test_permissions_failures_and_truncation(self) -> None:
        viewer = Principal.for_user(
            user_id=uuid4(), org_id=uuid4(), role=Role.VIEWER, session_id=None
        )
        restricted = _EchoTool()
        restricted.permission = Permission.RECORDS_READ_SENSITIVE
        gateway = ToolGateway(
            tools={
                "echo": restricted,
                "big": _EchoTool({"blob": "x" * 10_000}),
                "bad": _EchoTool(fail=True),
            },
            max_result_chars=100,
        )
        ctx = ToolContext(org_id=uuid4(), dataset_id=uuid4(), principal=viewer)
        denied = await gateway.execute(ToolCall(id="1", name="echo", arguments={}), ctx)
        failed = await gateway.execute(ToolCall(id="2", name="bad", arguments={}), ctx)
        big = await gateway.execute(ToolCall(id="3", name="big", arguments={}), ctx)
        assert denied.is_error and "Not permitted" in denied.content
        assert failed.is_error and "boom" not in failed.content  # no internals to the model
        assert len(big.content) < 200 and big.content.endswith('"[truncated]"')
