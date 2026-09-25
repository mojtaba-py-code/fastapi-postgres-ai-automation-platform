"""SQL builders for row-level security and grants, used by Alembic migrations.

This is a *stable* API: migrations are immutable history, so changing what a
helper emits requires a new migration rather than editing the helper.
Identifiers are validated because they are interpolated into DDL.
"""

from __future__ import annotations

import os
import re

_IDENTIFIER = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def ident(name: str) -> str:
    if not _IDENTIFIER.fullmatch(name):
        raise ValueError(f"unsafe SQL identifier: {name!r}")
    return name


def app_role() -> str:
    """Role that receives least-privilege grants (created by the DB bootstrap)."""
    return ident(os.environ.get("NEXUSFLOW_DATABASE__APP_ROLE", "nexusflow_app"))


def enable_rls(table: str) -> list[str]:
    # FORCE makes policies apply to the table owner as well (defence in depth).
    t = ident(table)
    return [
        f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {t} FORCE ROW LEVEL SECURITY",
    ]


def tenant_policy(table: str, column: str = "org_id") -> str:
    t, c = ident(table), ident(column)
    return (
        f"CREATE POLICY {t}_tenant_isolation ON {t} "
        f"USING ({c} = nf_current_org()) WITH CHECK ({c} = nf_current_org())"
    )


def grant(table: str, privileges: str, role: str) -> str:
    allowed = {"SELECT", "INSERT", "UPDATE", "DELETE"}
    parts = [p.strip().upper() for p in privileges.split(",")]
    for part in parts:
        base = part.split("(", 1)[0].strip()
        if base not in allowed:
            raise ValueError(f"unexpected privilege {part!r}")
    return f"GRANT {', '.join(parts)} ON {ident(table)} TO {ident(role)}"


def tenant_table_security(
    table: str, role: str, privileges: str = "SELECT, INSERT, UPDATE, DELETE"
) -> list[str]:
    """Standard treatment for a tenant-owned table."""
    return [*enable_rls(table), tenant_policy(table), grant(table, privileges, role)]


_DOLLAR_TAG = re.compile(r"\$[A-Za-z_]*\$")


def split_sql(script: str) -> list[str]:
    """Split a SQL script into single statements.

    The asyncpg driver executes prepared statements, which accept exactly one
    command. Semicolons inside single-quoted strings and dollar-quoted function
    bodies are preserved.
    """
    statements: list[str] = []
    buffer: list[str] = []
    index, length = 0, len(script)
    in_quote = False
    dollar_tag: str | None = None
    while index < length:
        char = script[index]
        if dollar_tag is not None:
            if script.startswith(dollar_tag, index):
                buffer.append(dollar_tag)
                index += len(dollar_tag)
                dollar_tag = None
            else:
                buffer.append(char)
                index += 1
            continue
        if in_quote:
            buffer.append(char)
            if char == "'":
                if script.startswith("''", index):
                    buffer.append("'")
                    index += 2
                    continue
                in_quote = False
            index += 1
            continue
        if char == "'":
            in_quote = True
        elif char == "$" and (match := _DOLLAR_TAG.match(script, index)):
            dollar_tag = match.group(0)
            buffer.append(dollar_tag)
            index += len(dollar_tag)
            continue
        elif char == ";":
            statement = "".join(buffer).strip()
            if statement:
                statements.append(statement)
            buffer = []
            index += 1
            continue
        buffer.append(char)
        index += 1
    tail = "".join(buffer).strip()
    if tail:
        statements.append(tail)
    return statements
