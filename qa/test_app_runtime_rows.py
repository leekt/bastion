#!/usr/bin/env python3
"""Regression checks for app-runtime row proof-focus classification."""

from __future__ import annotations

from app_runtime_rows import runtime_test_instructions, tracker_rows


def row_by_id(row_id: str) -> dict[str, object]:
    for row in tracker_rows():
        if row.get("ID") == row_id:
            return row
    raise AssertionError(f"missing tracker row {row_id}")


def main() -> None:
    ui_022 = runtime_test_instructions(row_by_id("UI-022"))
    assert "authenticated REST/MCP runtime response" not in ui_022

    api_001 = runtime_test_instructions(row_by_id("API-001"))
    assert "authenticated REST/MCP runtime response" in api_001

    explicit_rest = runtime_test_instructions({
        "ID": "UI-999",
        "Surface": "Settings",
        "Feature": "REST health sample",
        "User story": "As a tester, I want an explicit REST proof term.",
        "Expected behaviour": "REST endpoint responds.",
    })
    assert "authenticated REST/MCP runtime response" in explicit_rest


if __name__ == "__main__":
    main()
