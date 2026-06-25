#!/usr/bin/env python3
"""Build the canonical Bastion feature-status workbook.

This intentionally uses only the Python standard library so the tracker can be
rebuilt in this repo without network access or extra spreadsheet packages.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from app_runtime_rows import (
    LIVE_RUNTIME_BLOCKED_IDS,
    SEEDED_PAIRED_RUNTIME_IDS,
    live_runtime_evidence_template,
    runtime_evidence_template,
    runtime_pending_ids,
    runtime_pending_rows,
)


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "feature_status_source.json"
OUTPUT = ROOT / "feature_status.xlsx"
LEGACY_CSV = ROOT.parent / "docs" / "feature_user_story_tracker.csv"
AVAILABLE_CHECKS = ROOT / "run_available_checks.sh"


TEST_STATUS_VALUES = [
    "Pass",
    "Blocked in this environment",
    "Pending",
    "Pass by static inspection",
]
ALLOWED_TEST_STATUSES = set(TEST_STATUS_VALUES)

FEATURE_STATUS_VALUES = [
    "Implemented",
    "Deferred from UI",
    "Implemented for display; management deferred",
]
ALLOWED_FEATURE_STATUSES = set(FEATURE_STATUS_VALUES)

RUNTIME_RESULT_VALUES = [
    "pass",
    "fail",
    "blocked",
]

DEFERRED_UI_REQUIRED_TERMS = (
    "deferred",
    "CLI/MCP/REST",
)

ALLOWED_SURFACES = {
    "App lifecycle",
    "Audit core",
    "Audit history",
    "CLI",
    "Core Ethereum",
    "Core policy",
    "Core signing",
    "Core storage",
    "Core update",
    "Diagnostics",
    "Diagnostics core",
    "Install/runtime",
    "MCP",
    "Menu bar",
    "Notifications",
    "Pairing wizard",
    "Policy merge",
    "Preflight/simulation",
    "Provider trust",
    "REST",
    "Service UI bridge",
    "Service lifecycle",
    "Settings",
    "Shared UI",
    "Signing approval",
    "Silent receipt",
    "State reporting",
    "Submission tracking",
    "Temporary sessions",
    "Tracker",
    "Wallet groups",
    "XPC/security",
}

EXPECTED_APP_RUNTIME_PENDING_COUNT = 26
APP_RUNTIME_GATE = "qa/run_app_runtime_user_story_checks.sh"
LIVE_RUNTIME_GATE = "qa/run_live_runtime_checks.sh"
CURRENT_APP_RUNTIME_EVIDENCE = ROOT.parent / "dist" / "app-runtime-evidence.current.json"
CURRENT_LIVE_RUNTIME_EVIDENCE = ROOT.parent / "dist" / "live-runtime-evidence.current-blocked.json"
SEEDED_PAIRED_RUNTIME_GATE = "qa/run_seeded_paired_runtime_checks.sh"
CODE_SIGNING_REPAIR_COMMAND = "scripts/dev-enable-codesign-keychain-access.sh"
CODE_SIGNING_CHECK_REPAIR_COMMAND = (
    f"{CODE_SIGNING_REPAIR_COMMAND} --check && {CODE_SIGNING_REPAIR_COMMAND}"
)
SIGNED_REBUILD_COMMAND = "scripts/dev-rebuild-signed.sh"
CODE_SIGNING_CHECK_REPAIR_REBUILD_COMMAND = (
    f"{CODE_SIGNING_CHECK_REPAIR_COMMAND} && {SIGNED_REBUILD_COMMAND}"
)
SEEDED_PAIRED_RUNTIME_BLOCKER = (
    ROOT.parent
    / "dist"
    / "app-runtime-artifacts"
    / "seeded-paired-runtime"
    / "seeded-paired-runtime-blocker.log"
)
RUNTIME_PREREQS_SHEET = "Runtime Prereqs"
CODE_COVERAGE_SHEET = "Code Coverage"
TEST_MATRIX_SHEET = "Test Matrix"
ERROR_LEDGER_SHEET = "Error Ledger"
DEFAULT_APP_PATH = Path.home() / "Applications" / "Bastion Dev.app"
LIFECYCLE_EVIDENCE_DIR = ROOT.parent / "dist" / "lifecycle"
RELEASE_CANDIDATE_APP_PATH = ROOT.parent / "dist" / "release" / "Bastion.app"
SYSTEM_INSTALL_APP_PATH = Path("/Applications/Bastion.app")
REQUIRED_LIVE_PHASES = [
    "fresh-install",
    "reinstall",
    "post-reboot",
    "post-login",
    "notification-click",
]

APP_SWIFT_ROOTS = [
    ROOT.parent / "BastionShared",
    ROOT.parent / "bastion",
]

CODE_COVERAGE_PATTERNS = [
    "BastionShared/**/*.swift",
    "bastion/**/*.swift",
    "bastion-cli/**/*.swift",
    "mcp/src/**/*.ts",
    "scripts/*.sh",
]

APP_SOURCE_FRESHNESS_PATTERNS = [
    "BastionShared/**/*.swift",
    "bastion/**/*.swift",
    "bastion-cli/**/*.swift",
    "bastion/**/*.entitlements",
    "bastion-cli/**/*.entitlements",
    "bastion.xcodeproj/project.pbxproj",
]

APP_RUNTIME_BINARY_RELATIVE_PATHS = [
    "Contents/MacOS/bastion",
    "Contents/MacOS/bastion-cli",
    "Contents/Helpers/bastion-helper.app/Contents/MacOS/bastion-helper",
]

HEADERS = [
    "ID",
    "Surface",
    "Feature",
    "User story",
    "Expected behaviour",
    "Code evidence",
    "Feature status",
    "Test status",
    "Test evidence",
    "Errors documented",
    "Fix status",
    "Retest status",
    "Notes",
]

REQUIRED_NONEMPTY_HEADERS = [header for header in HEADERS if header != "Notes"]

SWIFT_REF_RE = re.compile(r"(?:BastionShared|bastion|bastionTests|bastion-cli|mcp)/[A-Za-z0-9_./+-]+\.swift")
REPO_FILE_REF_RE = re.compile(
    r"(?:\./)?"
    r"(?:(?:BastionShared|bastion|bastionTests|bastion-cli|mcp|qa|scripts|docs)/[A-Za-z0-9_./+-]+"
    r"|(?:KNOWN_ISSUES|OVERVIEW|PLAN|README|ui_todo))"
    r"\.(?:swift|ts|sh|md|py|json|xlsx|c|h|plist|entitlements)"
    r"(?![A-Za-z0-9_])"
)
ID_RE = re.compile(r"^(API|CLI|CORE|QA|UI)-(\d{3})$")
TEST_SUMMARY_RE = re.compile(r"Test run with (\d+ tests in \d+ suites) passed")
TRACKER_TEST_COUNT_RE = re.compile(r"\d+ tests in \d+ suites")
TEST_FILTER_RE = re.compile(r'DETERMINISTIC_TEST_FILTER="([^"]+)"')
STALE_APP_RUNTIME_COUNT_RE = re.compile(
    r"\b(?:28|29|30|31|32|33|34|35|36|37|38|39|60|66)-row\b"
    r"|\b(?:28|29|30|31|32|33|34|35|36|37|38|39|60|66)\s+(?:non-core\s+)?runtime-pending\b"
    r"|\b(?:28|29|30|31|32|33|34|35|36|37|38|39|60|66)\s+app-runtime\b"
    r"|\b(?:28|29|30|31|32|33|34|35|36|37|38|39|60|66)\s+runtime\b"
    r"|\b(?:28|29|30|31|32|33|34|35|36|37|38|39|60|66)\s+user-story\b"
    r"|\bthose\s+(?:28|29|30|31|32|33|34|35|36|37|38|39|60|66)\s+rows\b"
    r"|\bnon-core\s+runtime-pending\b"
)
STALE_XCODE_RUNTIME_BLOCKER_RE = re.compile(
    r"Full xcodebuild test still requires a full Xcode developer directory"
    r"|Xcode test blocked"
    r"|Xcode/app launch is unavailable"
    r"|app launch/full Xcode is unavailable"
    r"|full Xcode/app runtime"
    r"|full app runtime"
    r"|pending app run"
    r"|pending app runtime"
    r"|pending configured RPC/network app runtime"
    r"|blocked by full Xcode",
    re.IGNORECASE,
)
STALE_MANUAL_UI_PROOF_RE = re.compile(
    r"\bmanual\s+(?:visual|edit/save|posture|add target|target removal|global cap|authentication|zerodev|add rpc|template|address-book|high-value|policy-history|policy simulator|row expansion|signed-app sidebar)",
    re.IGNORECASE,
)
STALE_STATIC_EVIDENCE_RE = re.compile(
    r"\bStatic source/test mapping\b"
    r"|\bstatic-only\b"
    r"|\bonly static review evidence\b"
    r"|\bstatic inspection\b"
    r"|\bstatically inspected\b"
    r"|\bstatic evidence\b"
    r"|\bstatic/UI typecheck\b",
    re.IGNORECASE,
)
UNRESOLVED_PLACEHOLDER_RE = re.compile(r"\b(?:todo|tbd|dummy)\b", re.IGNORECASE)
VAGUE_RETEST_STATUS_VALUES = {"passed", "retest passed", "fixed"}
VAGUE_RETEST_STATUS_PREFIXES = ("retest passed ",)
VAGUE_FIX_STATUS_VALUES = {"fixed", "no code change needed; runtime pending"}
VAGUE_FIX_STATUS_PREFIXES = ("no code change needed", "no production code change needed")
VAGUE_FIX_STATUS_RE = re.compile(r"\bruntime pending\b", re.IGNORECASE)
VAGUE_ERRORS_DOCUMENTED_VALUES = {"none found in this pass.", "none found.", "none."}
VAGUE_ERRORS_DOCUMENTED_RE = re.compile(
    r"\bNo source-level (?:auth/CSRF )?(?:logistics or UX )?(?:error|issue) found\b"
    r"|\bno new (?:source-level |project ID |project ID precedence |audit |status tracking |merge |crash-collection |logistics or UX error |storage )?issue found\b"
    r"|\bno (?:MCP wallet tool argument-contract |new )?(?:logistics or UX )?(?:error|issue) found\b"
    r"|\bno source-level logistics or UX defect\b"
    r"|\b(?:command validation and output path|command input path|command paths|command path|target validation and XPC result handling|state loop) reviewed\b",
    re.IGNORECASE,
)
VAGUE_COVERAGE_DEFLECTION_RE = re.compile(
    r"\b(?:remains covered|covered by separate)\b",
    re.IGNORECASE,
)
VAGUE_FUTURE_FEATURE_RE = re.compile(r"\bfuture feature\b", re.IGNORECASE)
VAGUE_SHELL_UNAVAILABLE_RE = re.compile(
    r"\bnot available from this shell\b"
    r"|\bunavailable from this shell\b"
    r"|\bbecause this shell cannot\b",
    re.IGNORECASE,
)
VAGUE_MUST_VERIFY_RE = re.compile(r"\bmust verify\b", re.IGNORECASE)
VAGUE_NOT_YET_RE = re.compile(r"\bnot yet\b", re.IGNORECASE)
VAGUE_PARTIAL_PREFIX_RE = re.compile(r"\bPartial:", re.IGNORECASE)
VAGUE_PARTIAL_SIGNED_APP_RUNTIME_RE = re.compile(r"\bPartial signed-app runtime\b", re.IGNORECASE)
VAGUE_PENDING_NATIVE_RE = re.compile(
    r"\b(?:still|remain|remains) pending native signed-app UI automation\b"
    r"|\bpending native UI observation\b",
    re.IGNORECASE,
)
VAGUE_STILL_PENDING_RE = re.compile(r"\bstill pending\b", re.IGNORECASE)
VAGUE_REMAINS_PENDING_RE = re.compile(r"\bremains? pending\b", re.IGNORECASE)
VAGUE_STILL_REQUIRES_RE = re.compile(
    r"\bstill require(?:s|d)?\b|\bis still required\b",
    re.IGNORECASE,
)
VAGUE_RUNTIME_PLACEHOLDER_RE = re.compile(
    r"\bpending app/bundler runtime\b"
    r"|\bpending app/network runtime\b"
    r"|\bpending app/runtime testing\b"
    r"|\bpending runtime/UI automation\b",
    re.IGNORECASE,
)
VAGUE_RUNTIME_DEPENDENT_RE = re.compile(r"\bruntime[- ]dependent\b", re.IGNORECASE)
VAGUE_SIGNED_APP_APP_RUNTIME_RE = re.compile(
    r"\bpending signed-app app-runtime evidence\b"
    r"|\bpending signed-app runtime evidence\b",
    re.IGNORECASE,
)
VAGUE_REQUIRES_APP_RUNTIME_EVIDENCE_RE = re.compile(
    r"\brequires (?:signed-app )?app-runtime evidence\b",
    re.IGNORECASE,
)
VAGUE_PENDING_REBUILD_RE = re.compile(r"\bpending rebuild\b", re.IGNORECASE)
VAGUE_XCODE_ONLY_BLOCKER_RE = re.compile(r"\bxcodebuild-only blocker\b", re.IGNORECASE)
PROOF_GAP_RE = re.compile(r"Remaining proof gap:|Runtime proof gap:", re.IGNORECASE)
SIGNED_APP_BOUNDARY_RE = re.compile(
    r"Signed-app boundary evidence:"
    r"|signed-app boundary subset"
    r"|Signed-app runtime evidence:"
    r"|Current signed-app",
    re.IGNORECASE,
)


def app_runtime_count_phrases(count: int) -> list[str]:
    return [
        f"{count} app-runtime user-story rows",
        f"{count}-row JSON runtime evidence template",
        f"{count} app-runtime pending rows",
        f"those {count} rows",
    ]
ARTIFACT_REF_RE = re.compile(r"\bArtifact:\s*(\S+)")


def clean_artifact_ref(raw_path: str) -> str:
    return raw_path.rstrip(".,;:)")


def resolve_artifact_path(raw_path: str) -> Path:
    path = Path(clean_artifact_ref(raw_path))
    if path.is_absolute():
        return path
    return ROOT.parent / path


def col_name(index: int) -> str:
    out = ""
    while index:
        index, rem = divmod(index - 1, 26)
        out = chr(65 + rem) + out
    return out


def cell(ref: str, value: object, style: int | None = None) -> str:
    style_attr = f' s="{style}"' if style is not None else ""
    if value is None:
        return f'<c r="{ref}"{style_attr}/>'
    text = escape(str(value))
    return f'<c r="{ref}" t="inlineStr"{style_attr}><is><t>{text}</t></is></c>'


def row_xml(row_idx: int, values: list[object], style: int | None = None) -> str:
    cells = []
    for col_idx, value in enumerate(values, start=1):
        cells.append(cell(f"{col_name(col_idx)}{row_idx}", value, style))
    return f'<row r="{row_idx}">{"".join(cells)}</row>'


def list_validation_xml(sqref: str, values: list[str]) -> str:
    formula = '"' + ",".join(values) + '"'
    return (
        f'<dataValidation type="list" allowBlank="1" showErrorMessage="1" sqref="{escape(sqref)}">'
        f"<formula1>{escape(formula)}</formula1>"
        "</dataValidation>"
    )


def data_validations_xml(validations: list[str]) -> str:
    if not validations:
        return ""
    return f'<dataValidations count="{len(validations)}">{"".join(validations)}</dataValidations>'


def sheet_xml(rows: list[list[object]], widths: list[float], validations: list[str] | None = None) -> str:
    cols = "".join(
        f'<col min="{i}" max="{i}" width="{width}" customWidth="1"/>'
        for i, width in enumerate(widths, start=1)
    )
    body = [row_xml(1, rows[0], 1)]
    for idx, values in enumerate(rows[1:], start=2):
        body.append(row_xml(idx, values, 0))
    dimension = f"A1:{col_name(len(rows[0]))}{len(rows)}"
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <dimension ref="{dimension}"/>
  <sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>
  <cols>{cols}</cols>
  <sheetData>{"".join(body)}</sheetData>
  <autoFilter ref="{dimension}"/>
  {data_validations_xml(validations or [])}
</worksheet>'''


def workbook_xml() -> str:
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Feature Status" sheetId="1" r:id="rId1"/>
    <sheet name="Summary" sheetId="2" r:id="rId2"/>
    <sheet name="App Runtime Sweep" sheetId="3" r:id="rId3"/>
    <sheet name="Live Runtime Sweep" sheetId="4" r:id="rId4"/>
    <sheet name="Closure Checklist" sheetId="5" r:id="rId5"/>
    <sheet name="Completion Audit" sheetId="6" r:id="rId6"/>
    <sheet name="Runtime Prereqs" sheetId="7" r:id="rId7"/>
    <sheet name="Open Issues" sheetId="8" r:id="rId8"/>
    <sheet name="Code Coverage" sheetId="9" r:id="rId9"/>
    <sheet name="Test Matrix" sheetId="10" r:id="rId10"/>
    <sheet name="Error Ledger" sheetId="11" r:id="rId11"/>
  </sheets>
</workbook>'''


def styles_xml() -> str:
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2">
    <font><sz val="11"/><name val="Aptos"/></font>
    <font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Aptos"/></font>
  </fonts>
  <fills count="3">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FF1F2937"/><bgColor indexed="64"/></patternFill></fill>
  </fills>
  <borders count="2">
    <border><left/><right/><top/><bottom/><diagonal/></border>
    <border><left style="thin"><color rgb="FFD1D5DB"/></left><right style="thin"><color rgb="FFD1D5DB"/></right><top style="thin"><color rgb="FFD1D5DB"/></top><bottom style="thin"><color rgb="FFD1D5DB"/></bottom><diagonal/></border>
  </borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="2">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
    <xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf>
  </cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>'''


def rels_xml() -> str:
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>'''


def workbook_rels_xml() -> str:
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet3.xml"/>
  <Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet4.xml"/>
  <Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet5.xml"/>
  <Relationship Id="rId6" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet6.xml"/>
  <Relationship Id="rId7" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet7.xml"/>
  <Relationship Id="rId8" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet8.xml"/>
  <Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet9.xml"/>
  <Relationship Id="rId10" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet10.xml"/>
  <Relationship Id="rId11" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet11.xml"/>
  <Relationship Id="rId12" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>'''


def content_types_xml() -> str:
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet3.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet4.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet5.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet6.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet7.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet8.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet9.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet10.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet11.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
  <Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
  <Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>'''


def core_xml() -> str:
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:title>Bastion Feature Status</dc:title>
  <dc:creator>Codex</dc:creator>
  <cp:lastModifiedBy>Codex</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified>
</cp:coreProperties>'''


def app_xml() -> str:
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
  <Application>Codex</Application>
</Properties>'''


def relative_repo_path(path: Path) -> str:
    return path.relative_to(ROOT.parent).as_posix()


def validate_entries(entries: object) -> list[dict[str, object]]:
    if not isinstance(entries, list):
        raise SystemExit(f"{SOURCE} must contain a JSON list")

    normalized: list[dict[str, object]] = []
    ids: set[str] = set()
    duplicate_ids: set[str] = set()
    ids_by_prefix: dict[str, set[int]] = {}
    bad_statuses: list[str] = []
    bad_feature_statuses: list[str] = []
    bad_surfaces: list[str] = []
    bad_ids: list[str] = []
    missing_fields: list[str] = []
    extra_fields: list[str] = []
    non_string_fields: list[str] = []
    whitespace_fields: list[str] = []
    empty_fields: list[str] = []
    missing_code_references: list[str] = []
    stale_environment_blockers: list[str] = []
    stale_manual_ui_proof: list[str] = []
    stale_static_evidence: list[str] = []
    unresolved_placeholders: list[str] = []
    vague_retest_statuses: list[str] = []
    vague_fix_statuses: list[str] = []
    vague_errors_documented: list[str] = []
    vague_coverage_deflections: list[str] = []
    vague_future_features: list[str] = []
    vague_shell_unavailable: list[str] = []
    vague_must_verify: list[str] = []
    vague_not_yet: list[str] = []
    vague_partial_prefixes: list[str] = []
    vague_partial_signed_app_runtime: list[str] = []
    vague_pending_native: list[str] = []
    vague_still_pending: list[str] = []
    vague_remains_pending: list[str] = []
    vague_still_requires: list[str] = []
    vague_runtime_placeholders: list[str] = []
    vague_runtime_dependent: list[str] = []
    vague_signed_app_app_runtime: list[str] = []
    vague_requires_app_runtime_evidence: list[str] = []
    vague_pending_rebuild: list[str] = []
    vague_xcode_only_blockers: list[str] = []
    stale_pass_runtime_gaps: list[str] = []
    signed_app_boundary_missing_artifacts: list[str] = []
    deferred_ui_contract_errors: list[str] = []
    blocked_ids: set[str] = set()
    blocked_rows_missing_live_gate: list[str] = []
    retest_artifact_errors: list[str] = []
    app_runtime_pending_ids: set[str] = set()
    qa_tracker_text = ""
    test_count_references: dict[str, set[str]] = {}

    for idx, item in enumerate(entries, start=1):
        if not isinstance(item, dict):
            raise SystemExit(f"row {idx} must be an object")
        normalized.append(item)

        row_id = str(item.get("ID", "")).strip()
        if not row_id:
            missing_fields.append(f"row {idx}: ID")
        elif row_id in ids:
            duplicate_ids.add(row_id)
        elif match := ID_RE.fullmatch(row_id):
            ids_by_prefix.setdefault(match.group(1), set()).add(int(match.group(2)))
        else:
            bad_ids.append(f"row {idx}: {row_id}")
        ids.add(row_id)

        for header in HEADERS:
            if header not in item:
                missing_fields.append(f"{row_id or f'row {idx}'}: {header}")
        for header in sorted(set(item) - set(HEADERS)):
            extra_fields.append(f"{row_id or f'row {idx}'}: {header}")
        for header in HEADERS:
            if header in item and not isinstance(item[header], str):
                non_string_fields.append(f"{row_id or f'row {idx}'}: {header}")
            elif header in item and item[header] != item[header].strip():
                whitespace_fields.append(f"{row_id or f'row {idx}'}: {header}")

        for header in REQUIRED_NONEMPTY_HEADERS:
            if header in item and not str(item.get(header, "")).strip():
                empty_fields.append(f"{row_id or f'row {idx}'}: {header}")

        test_status = item.get("Test status")
        if test_status not in ALLOWED_TEST_STATUSES:
            bad_statuses.append(f"{row_id or f'row {idx}'}: {test_status!r}")
        elif test_status == "Blocked in this environment":
            blocked_ids.add(row_id)
            live_gate_evidence = " ".join(
                str(item.get(header, ""))
                for header in ("Test evidence", "Retest status", "Notes")
            )
            if "qa/run_live_runtime_checks.sh" not in live_gate_evidence:
                blocked_rows_missing_live_gate.append(row_id or f"row {idx}")

        feature_status = item.get("Feature status")
        if feature_status not in ALLOWED_FEATURE_STATUSES:
            bad_feature_statuses.append(f"{row_id or f'row {idx}'}: {feature_status!r}")
        elif feature_status == "Deferred from UI":
            deferred_text = " ".join(
                str(item.get(header, ""))
                for header in (
                    "Expected behaviour",
                    "Test evidence",
                    "Errors documented",
                    "Fix status",
                    "Retest status",
                    "Notes",
                )
            )
            missing_terms = [term for term in DEFERRED_UI_REQUIRED_TERMS if term not in deferred_text]
            if missing_terms:
                deferred_ui_contract_errors.append(
                    f"{row_id or f'row {idx}'}: missing " + ", ".join(missing_terms)
                )

        surface = item.get("Surface")
        if surface not in ALLOWED_SURFACES:
            bad_surfaces.append(f"{row_id or f'row {idx}'}: {surface!r}")

        code_evidence = item.get("Code evidence")
        if isinstance(code_evidence, str) and not REPO_FILE_REF_RE.search(code_evidence):
            missing_code_references.append(row_id or f"row {idx}")

        errors_documented = item.get("Errors documented")
        if (
            item.get("Test status") == "Pass"
            and isinstance(errors_documented, str)
            and (
                errors_documented.strip().lower() in VAGUE_ERRORS_DOCUMENTED_VALUES
                or VAGUE_ERRORS_DOCUMENTED_RE.search(errors_documented)
            )
        ):
            vague_errors_documented.append(f"{row_id or f'row {idx}'}: {errors_documented}")

        fix_status = item.get("Fix status")
        if (
            item.get("Test status") == "Pass"
            and isinstance(fix_status, str)
            and (
                fix_status.strip().lower() in VAGUE_FIX_STATUS_VALUES
                or fix_status.strip().lower().startswith(VAGUE_FIX_STATUS_PREFIXES)
                or VAGUE_FIX_STATUS_RE.search(fix_status)
            )
        ):
            vague_fix_statuses.append(f"{row_id or f'row {idx}'}: {fix_status}")

        retest_status = item.get("Retest status")
        if (
            item.get("Test status") == "Pass"
            and isinstance(retest_status, str)
            and (
                retest_status.strip().lower() in VAGUE_RETEST_STATUS_VALUES
                or retest_status.strip().lower().startswith(VAGUE_RETEST_STATUS_PREFIXES)
            )
        ):
            vague_retest_statuses.append(f"{row_id or f'row {idx}'}: {retest_status}")
        if isinstance(retest_status, str) and "Evidence:" in retest_status:
            artifact_match = ARTIFACT_REF_RE.search(retest_status)
            if not artifact_match:
                retest_artifact_errors.append(f"{row_id or f'row {idx}'}: Retest status must cite Artifact:")
            else:
                artifact_path = resolve_artifact_path(artifact_match.group(1))
                if not artifact_path.exists():
                    retest_artifact_errors.append(
                        f"{row_id or f'row {idx}'}: Retest artifact does not exist: {clean_artifact_ref(artifact_match.group(1))}"
                    )
                elif not artifact_path.is_file():
                    retest_artifact_errors.append(
                        f"{row_id or f'row {idx}'}: Retest artifact must be a regular file: {clean_artifact_ref(artifact_match.group(1))}"
                    )
                elif artifact_path.stat().st_size == 0:
                    retest_artifact_errors.append(
                        f"{row_id or f'row {idx}'}: Retest artifact must not be empty: {clean_artifact_ref(artifact_match.group(1))}"
                    )
                else:
                    artifact_text = artifact_path.read_text(errors="replace")
                    expected_terms = (
                        ("row ID", row_id),
                        ("tracker Feature", item.get("Feature")),
                        ("tracker User story", item.get("User story")),
                        ("tracker Expected behaviour", item.get("Expected behaviour")),
                    )
                    for label, expected_value in expected_terms:
                        if isinstance(expected_value, str) and expected_value and expected_value not in artifact_text:
                            retest_artifact_errors.append(
                                f"{row_id or f'row {idx}'}: Retest artifact must mention the {label}: {clean_artifact_ref(artifact_match.group(1))}"
                            )

        if row_id == "QA-001":
            qa_tracker_text = " ".join(str(item.get(header, "")) for header in HEADERS)

        row_text = " ".join(str(item.get(header, "")) for header in HEADERS)
        if (
            item.get("Test status") == "Pass"
            and isinstance(retest_status, str)
            and f"Passed signed-app runtime sweep for {row_id} " in retest_status
            and re.search(r"Remaining proof gap:|Runtime proof gap:", row_text, re.IGNORECASE)
        ):
            stale_pass_runtime_gaps.append(row_id or f"row {idx}")
        placeholder_match = UNRESOLVED_PLACEHOLDER_RE.search(row_text)
        if placeholder_match:
            unresolved_placeholders.append(f"{row_id or f'row {idx}'}: {placeholder_match.group(0)}")
        coverage_deflection_match = VAGUE_COVERAGE_DEFLECTION_RE.search(row_text)
        if coverage_deflection_match:
            vague_coverage_deflections.append(f"{row_id or f'row {idx}'}: {coverage_deflection_match.group(0)}")
        future_feature_match = VAGUE_FUTURE_FEATURE_RE.search(row_text)
        if future_feature_match:
            vague_future_features.append(f"{row_id or f'row {idx}'}: {future_feature_match.group(0)}")
        shell_unavailable_match = VAGUE_SHELL_UNAVAILABLE_RE.search(row_text)
        if shell_unavailable_match:
            vague_shell_unavailable.append(f"{row_id or f'row {idx}'}: {shell_unavailable_match.group(0)}")
        must_verify_match = VAGUE_MUST_VERIFY_RE.search(row_text)
        if must_verify_match:
            vague_must_verify.append(f"{row_id or f'row {idx}'}: {must_verify_match.group(0)}")
        not_yet_match = VAGUE_NOT_YET_RE.search(row_text)
        if not_yet_match:
            vague_not_yet.append(f"{row_id or f'row {idx}'}: {not_yet_match.group(0)}")
        partial_prefix_match = VAGUE_PARTIAL_PREFIX_RE.search(row_text)
        if partial_prefix_match:
            vague_partial_prefixes.append(f"{row_id or f'row {idx}'}: {partial_prefix_match.group(0)}")
        partial_signed_app_runtime_match = VAGUE_PARTIAL_SIGNED_APP_RUNTIME_RE.search(row_text)
        if partial_signed_app_runtime_match:
            vague_partial_signed_app_runtime.append(
                f"{row_id or f'row {idx}'}: {partial_signed_app_runtime_match.group(0)}"
            )
        pending_native_match = VAGUE_PENDING_NATIVE_RE.search(row_text)
        if pending_native_match:
            vague_pending_native.append(f"{row_id or f'row {idx}'}: {pending_native_match.group(0)}")
        still_pending_match = VAGUE_STILL_PENDING_RE.search(row_text)
        if still_pending_match:
            vague_still_pending.append(f"{row_id or f'row {idx}'}: {still_pending_match.group(0)}")
        remains_pending_match = VAGUE_REMAINS_PENDING_RE.search(row_text)
        if remains_pending_match:
            vague_remains_pending.append(f"{row_id or f'row {idx}'}: {remains_pending_match.group(0)}")
        still_requires_match = VAGUE_STILL_REQUIRES_RE.search(row_text)
        if still_requires_match:
            vague_still_requires.append(f"{row_id or f'row {idx}'}: {still_requires_match.group(0)}")
        runtime_placeholder_match = VAGUE_RUNTIME_PLACEHOLDER_RE.search(row_text)
        if runtime_placeholder_match:
            vague_runtime_placeholders.append(f"{row_id or f'row {idx}'}: {runtime_placeholder_match.group(0)}")
        runtime_dependent_match = VAGUE_RUNTIME_DEPENDENT_RE.search(row_text)
        if runtime_dependent_match:
            vague_runtime_dependent.append(f"{row_id or f'row {idx}'}: {runtime_dependent_match.group(0)}")
        signed_app_app_runtime_match = VAGUE_SIGNED_APP_APP_RUNTIME_RE.search(row_text)
        if signed_app_app_runtime_match:
            vague_signed_app_app_runtime.append(
                f"{row_id or f'row {idx}'}: {signed_app_app_runtime_match.group(0)}"
            )
        requires_app_runtime_evidence_match = VAGUE_REQUIRES_APP_RUNTIME_EVIDENCE_RE.search(row_text)
        if requires_app_runtime_evidence_match:
            vague_requires_app_runtime_evidence.append(
                f"{row_id or f'row {idx}'}: {requires_app_runtime_evidence_match.group(0)}"
            )
        pending_rebuild_match = VAGUE_PENDING_REBUILD_RE.search(row_text)
        if pending_rebuild_match:
            vague_pending_rebuild.append(f"{row_id or f'row {idx}'}: {pending_rebuild_match.group(0)}")
        xcode_only_blocker_match = VAGUE_XCODE_ONLY_BLOCKER_RE.search(row_text)
        if xcode_only_blocker_match:
            vague_xcode_only_blockers.append(f"{row_id or f'row {idx}'}: {xcode_only_blocker_match.group(0)}")
        stale_environment_match = STALE_XCODE_RUNTIME_BLOCKER_RE.search(row_text)
        if stale_environment_match:
            stale_environment_blockers.append(f"{row_id or f'row {idx}'}: {stale_environment_match.group(0)}")
        stale_manual_match = STALE_MANUAL_UI_PROOF_RE.search(row_text)
        if stale_manual_match:
            stale_manual_ui_proof.append(f"{row_id or f'row {idx}'}: {stale_manual_match.group(0)}")
        stale_static_match = STALE_STATIC_EVIDENCE_RE.search(row_text)
        if stale_static_match:
            stale_static_evidence.append(f"{row_id or f'row {idx}'}: {stale_static_match.group(0)}")

        row_test_counts = set()
        for value in item.values():
            if isinstance(value, str):
                row_test_counts.update(TRACKER_TEST_COUNT_RE.findall(value))
        if row_test_counts:
            test_count_references[row_id or f"row {idx}"] = row_test_counts

    app_runtime_pending_ids = set(runtime_pending_ids(normalized))
    for item in normalized:
        row_id = str(item.get("ID", ""))
        if row_id not in app_runtime_pending_ids:
            continue
        for header in ("Test evidence", "Errors documented", "Fix status", "Retest status", "Notes"):
            value = str(item.get(header, ""))
            if SIGNED_APP_BOUNDARY_RE.search(value) and not ARTIFACT_REF_RE.search(value):
                signed_app_boundary_missing_artifacts.append(f"{row_id}: {header}")

    errors: list[str] = []
    if duplicate_ids:
        errors.append("duplicate IDs: " + ", ".join(sorted(duplicate_ids)))
    if bad_ids:
        errors.append("non-canonical IDs:\n  " + "\n  ".join(bad_ids))
    missing_sequence_ids: list[str] = []
    for prefix, numbers in sorted(ids_by_prefix.items()):
        if not numbers:
            continue
        for number in range(1, max(numbers) + 1):
            if number not in numbers:
                missing_sequence_ids.append(f"{prefix}-{number:03d}")
    if missing_sequence_ids:
        errors.append("missing IDs in prefix sequences:\n  " + "\n  ".join(missing_sequence_ids))
    if missing_fields:
        errors.append("missing required fields:\n  " + "\n  ".join(missing_fields))
    if extra_fields:
        errors.append("non-canonical fields:\n  " + "\n  ".join(extra_fields))
    if non_string_fields:
        errors.append("canonical fields must be strings:\n  " + "\n  ".join(non_string_fields))
    if whitespace_fields:
        errors.append("canonical fields must not have leading or trailing whitespace:\n  " + "\n  ".join(whitespace_fields))
    if empty_fields:
        errors.append("empty required fields:\n  " + "\n  ".join(empty_fields))
    if bad_statuses:
        errors.append("non-canonical Test status values:\n  " + "\n  ".join(bad_statuses))
    if bad_feature_statuses:
        errors.append("non-canonical Feature status values:\n  " + "\n  ".join(bad_feature_statuses))
    if deferred_ui_contract_errors:
        errors.append(
            "Deferred-from-UI rows must name the deferred UI scope and CLI/MCP/REST backend coverage:\n  "
            + "\n  ".join(deferred_ui_contract_errors)
        )
    if bad_surfaces:
        errors.append("non-canonical Surface values:\n  " + "\n  ".join(bad_surfaces))
    if missing_code_references:
        errors.append("Code evidence must include at least one repository file reference:\n  " + "\n  ".join(missing_code_references))
    if stale_environment_blockers:
        errors.append(
            "tracker source contains stale Xcode/runtime blocker wording; use Runtime Prereqs for environment state:\n  "
            + "\n  ".join(stale_environment_blockers)
        )
    if stale_manual_ui_proof:
        errors.append(
            "tracker source contains stale manual UI-proof wording; cite native signed-app UI automation instead:\n  "
            + "\n  ".join(stale_manual_ui_proof)
        )
    if stale_static_evidence:
        errors.append(
            "tracker source contains stale static-inspection evidence wording; cite concrete deterministic coverage instead:\n  "
            + "\n  ".join(stale_static_evidence)
        )
    if unresolved_placeholders:
        errors.append(
            "tracker source contains unresolved placeholder wording:\n  "
            + "\n  ".join(unresolved_placeholders)
        )
    if vague_coverage_deflections:
        errors.append(
            "tracker source contains vague coverage deflection wording; name the concrete gate or runtime evidence instead:\n  "
            + "\n  ".join(vague_coverage_deflections)
        )
    if vague_future_features:
        errors.append(
            "tracker source contains vague future-feature wording; name the deferred scope and current coverage instead:\n  "
            + "\n  ".join(vague_future_features)
        )
    if vague_shell_unavailable:
        errors.append(
            "tracker source contains vague shell-unavailable wording; name the concrete signed-app proof gap instead:\n  "
            + "\n  ".join(vague_shell_unavailable)
        )
    if vague_must_verify:
        errors.append(
            "tracker source contains vague must-verify wording; name the concrete proof gap instead:\n  "
            + "\n  ".join(vague_must_verify)
        )
    if vague_not_yet:
        errors.append(
            "tracker source contains vague not-yet wording; name the concrete missing state instead:\n  "
            + "\n  ".join(vague_not_yet)
        )
    if vague_partial_prefixes:
        errors.append(
            "tracker source contains vague Partial-prefix wording; describe the passed subset and Remaining proof gap instead:\n  "
            + "\n  ".join(vague_partial_prefixes)
        )
    if vague_partial_signed_app_runtime:
        errors.append(
            "tracker source contains vague partial signed-app runtime wording; use Signed-app boundary evidence with the concrete proof instead:\n  "
            + "\n  ".join(vague_partial_signed_app_runtime)
        )
    if vague_pending_native:
        errors.append(
            "tracker source contains vague pending-native wording; name the concrete signed-app proof gap instead:\n  "
            + "\n  ".join(vague_pending_native)
        )
    if vague_still_pending:
        errors.append(
            "tracker source contains vague still-pending wording; name the concrete proof gap instead:\n  "
            + "\n  ".join(vague_still_pending)
        )
    if vague_remains_pending:
        errors.append(
            "tracker source contains vague remains-pending wording; use Remaining proof gap with the concrete proof instead:\n  "
            + "\n  ".join(vague_remains_pending)
        )
    if vague_still_requires:
        errors.append(
            "tracker source contains vague still-requires wording; use Remaining proof gap with the concrete proof instead:\n  "
            + "\n  ".join(vague_still_requires)
        )
    if vague_runtime_placeholders:
        errors.append(
            "tracker source contains vague runtime-placeholder wording; name the concrete runtime proof gap instead:\n  "
            + "\n  ".join(vague_runtime_placeholders)
        )
    if vague_runtime_dependent:
        errors.append(
            "tracker source contains vague runtime-dependent wording; name the concrete runtime proof gap instead:\n  "
            + "\n  ".join(vague_runtime_dependent)
        )
    if vague_signed_app_app_runtime:
        errors.append(
            "tracker source contains vague signed-app app-runtime wording; name the concrete runtime proof gap instead:\n  "
            + "\n  ".join(vague_signed_app_app_runtime)
        )
    if vague_requires_app_runtime_evidence:
        errors.append(
            "tracker source contains vague requires-app-runtime-evidence wording; name the concrete runtime proof gap instead:\n  "
            + "\n  ".join(vague_requires_app_runtime_evidence)
        )
    if vague_pending_rebuild:
        errors.append(
            "tracker source contains vague pending-rebuild wording; name the concrete rebuild proof gap instead:\n  "
            + "\n  ".join(vague_pending_rebuild)
        )
    if vague_xcode_only_blockers:
        errors.append(
            "tracker source contains vague xcodebuild-only blocker wording; name the concrete deterministic gate instead:\n  "
            + "\n  ".join(vague_xcode_only_blockers)
        )
    if stale_pass_runtime_gaps:
        errors.append(
            "passed signed-app runtime rows must not retain Remaining/Runtime proof gap text:\n  "
            + "\n  ".join(stale_pass_runtime_gaps)
        )
    if signed_app_boundary_missing_artifacts:
        errors.append(
            "app-runtime rows with signed-app boundary evidence must cite Artifact: in the source row:\n  "
            + "\n  ".join(signed_app_boundary_missing_artifacts)
        )
    if vague_retest_statuses:
        errors.append(
            "pass rows must describe concrete retest evidence, not vague Retest status text:\n  "
            + "\n  ".join(vague_retest_statuses)
        )
    if vague_fix_statuses:
        errors.append(
            "pass rows must describe the concrete fix state, not vague Fix status text:\n  "
            + "\n  ".join(vague_fix_statuses)
        )
    if vague_errors_documented:
        errors.append(
            "pass rows must describe reviewed errors or absence of defects, not vague Errors documented text:\n  "
            + "\n  ".join(vague_errors_documented)
        )
    if retest_artifact_errors:
        errors.append("Retest status artifact evidence is invalid:\n  " + "\n  ".join(retest_artifact_errors))
    if not blocked_ids <= LIVE_RUNTIME_BLOCKED_IDS:
        extra = sorted(blocked_ids - LIVE_RUNTIME_BLOCKED_IDS)
        details: list[str] = []
        if extra:
            details.append("unexpected blocked rows: " + ", ".join(extra))
        errors.append(
            "Blocked-in-environment rows must be part of the canonical live-runtime gate until individually closed:\n  "
            + "\n  ".join(details)
        )
    if blocked_rows_missing_live_gate:
        errors.append(
            "Blocked-in-environment rows must cite qa/run_live_runtime_checks.sh in test/retest evidence:\n  "
            + "\n  ".join(blocked_rows_missing_live_gate)
        )
    if len(app_runtime_pending_ids) > EXPECTED_APP_RUNTIME_PENDING_COUNT:
        errors.append(
            "app-runtime pending row count must either match the current signed-app sweep or be fully closed:\n  "
            f"expected at most {EXPECTED_APP_RUNTIME_PENDING_COUNT}, found {len(app_runtime_pending_ids)}\n  "
            + " ".join(sorted(app_runtime_pending_ids))
        )
    elif 0 < len(app_runtime_pending_ids) < EXPECTED_APP_RUNTIME_PENDING_COUNT:
        partial_failure_ids = sorted(
            str(row.get("ID", ""))
            for row in normalized
            if str(row.get("ID", "")) in app_runtime_pending_ids
            and row.get("Test status") == "Pending"
        )
        if partial_failure_ids:
            errors.append(
                "app-runtime pending row count must either match the current signed-app sweep or be fully closed:\n  "
                "partial signed-app failure rows must remain review artifacts until fixed and retested:\n  "
                + " ".join(partial_failure_ids)
            )
    if app_runtime_pending_ids and APP_RUNTIME_GATE not in qa_tracker_text:
        errors.append(f"QA-001 must cite {APP_RUNTIME_GATE} when app-runtime pending rows exist")
    if (app_runtime_pending_ids or blocked_ids) and RUNTIME_PREREQS_SHEET not in qa_tracker_text:
        errors.append(f"QA-001 must cite {RUNTIME_PREREQS_SHEET} when runtime prerequisite rows exist")
    if app_runtime_pending_ids:
        skipped_proof_gap_ids = sorted(
            str(row.get("ID", ""))
            for row in normalized
            if str(row.get("ID", "")) not in app_runtime_pending_ids
            and str(row.get("ID", "")) not in LIVE_RUNTIME_BLOCKED_IDS
            and str(row.get("ID", "")) != "QA-001"
            and PROOF_GAP_RE.search(" ".join(str(row.get(header, "")) for header in HEADERS))
        )
        if skipped_proof_gap_ids:
            errors.append(
                "proof-gap rows must be covered by the app-runtime sweep or live-runtime blocked set:\n  "
                + " ".join(skipped_proof_gap_ids)
            )
    stale_count_match = STALE_APP_RUNTIME_COUNT_RE.search(qa_tracker_text)
    if stale_count_match:
        errors.append(
            "QA-001 tracker evidence contains stale app-runtime row-count wording: "
            + stale_count_match.group(0)
        )
    for phrase in app_runtime_count_phrases(len(app_runtime_pending_ids)):
        if phrase not in qa_tracker_text:
            errors.append(f"QA-001 tracker evidence must cite current app-runtime count phrase: {phrase}")

    expected_test_count = deterministic_test_count()
    mismatched_test_counts: list[str] = []
    for ref_id, counts in sorted(test_count_references.items()):
        if counts != {expected_test_count}:
            mismatched_test_counts.append(f"{ref_id}: {', '.join(sorted(counts))}")
    if mismatched_test_counts:
        errors.append(
            "tracker deterministic test-count references must match qa/run_available_checks.sh "
            f"({expected_test_count}):\n  "
            + "\n  ".join(mismatched_test_counts)
        )

    missing_filter_names = missing_deterministic_filter_names()
    if missing_filter_names:
        errors.append(
            "DETERMINISTIC_TEST_FILTER names missing from bastionTests sources:\n  "
            + "\n  ".join(missing_filter_names)
        )

    referenced = referenced_swift_files(normalized)
    missing_references = sorted(ref for ref in referenced if not (ROOT.parent / ref).exists())
    if missing_references:
        errors.append("referenced Swift files do not exist:\n  " + "\n  ".join(missing_references))

    referenced_files = referenced_repo_files(normalized)
    missing_files = sorted(ref for ref in referenced_files if not (ROOT.parent / ref).exists())
    if missing_files:
        errors.append("referenced repository files do not exist:\n  " + "\n  ".join(missing_files))

    untracked_app_files = app_swift_files() - referenced
    if untracked_app_files:
        errors.append("app Swift files missing from tracker evidence:\n  " + "\n  ".join(sorted(untracked_app_files)))

    untracked_code_files = code_coverage_files() - referenced_files
    if untracked_code_files:
        errors.append("feature code files missing from tracker evidence:\n  " + "\n  ".join(sorted(untracked_code_files)))

    if errors:
        raise SystemExit("\n\n".join(errors))

    return normalized


def referenced_swift_files(entries: list[dict[str, object]]) -> set[str]:
    refs: set[str] = set()
    for item in entries:
        for value in item.values():
            if isinstance(value, str):
                refs.update(SWIFT_REF_RE.findall(value))
    return refs


def referenced_repo_files(entries: list[dict[str, object]]) -> set[str]:
    refs: set[str] = set()
    for item in entries:
        for value in item.values():
            if isinstance(value, str):
                for match in REPO_FILE_REF_RE.findall(value):
                    refs.add(match.removeprefix("./"))
    return refs


def deterministic_test_count() -> str:
    match = TEST_SUMMARY_RE.search(AVAILABLE_CHECKS.read_text())
    if not match:
        raise SystemExit(f"{AVAILABLE_CHECKS} must define DETERMINISTIC_TEST_SUMMARY with a test count")
    return match.group(1)


def deterministic_test_filter_names() -> list[str]:
    match = TEST_FILTER_RE.search(AVAILABLE_CHECKS.read_text())
    if not match:
        raise SystemExit(f"{AVAILABLE_CHECKS} must define DETERMINISTIC_TEST_FILTER")
    return [name for name in match.group(1).split("|") if name]


def missing_deterministic_filter_names() -> list[str]:
    test_text = "\n".join(path.read_text(errors="ignore") for path in (ROOT.parent / "bastionTests").glob("*.swift"))
    return [name for name in deterministic_test_filter_names() if name not in test_text]


def app_swift_files() -> set[str]:
    files: set[str] = set()
    for root in APP_SWIFT_ROOTS:
        if root.exists():
            files.update(relative_repo_path(path) for path in root.rglob("*.swift"))
    return files


def code_coverage_files() -> set[str]:
    files: set[str] = set()
    for pattern in CODE_COVERAGE_PATTERNS:
        files.update(relative_repo_path(path) for path in (ROOT.parent).glob(pattern) if path.is_file())
    return files


def code_area(repo_path: str) -> str:
    if repo_path.startswith("BastionShared/"):
        return "Shared Swift"
    if repo_path.startswith("bastion/"):
        return "App Swift"
    if repo_path.startswith("bastion-cli/"):
        return "CLI"
    if repo_path.startswith("mcp/src/"):
        return "MCP"
    if repo_path.startswith("scripts/"):
        return "Release/runtime script"
    return "Repository code"


def referenced_rows_by_file(entries: list[dict[str, object]]) -> dict[str, list[dict[str, object]]]:
    rows_by_file: dict[str, list[dict[str, object]]] = {}
    for item in entries:
        for ref in referenced_repo_files([item]):
            rows_by_file.setdefault(ref, []).append(item)
    return rows_by_file


def unmapped_code_coverage_files(entries: list[dict[str, object]]) -> set[str]:
    return code_coverage_files() - referenced_repo_files(entries)


def configured_app_path() -> Path:
    return Path(os.environ.get("BASTION_APP_PATH", str(DEFAULT_APP_PATH))).expanduser()


def configured_lifecycle_evidence_dir() -> Path:
    return Path(os.environ.get("BASTION_LIFECYCLE_EVIDENCE_DIR", str(LIFECYCLE_EVIDENCE_DIR))).expanduser()


def command_result(args: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return 127, str(exc)
    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    return result.returncode, output.strip()


def one_line(value: str) -> str:
    return " ".join(value.split())


def display_path(value: Path | str) -> str:
    text = str(value)
    for raw, replacement in (
        (str(ROOT.parent.resolve()), "<repo-root>"),
        (str(ROOT.parent), "<repo-root>"),
        (str(Path.home()), "$HOME"),
    ):
        if raw:
            text = text.replace(raw, replacement)
    return text


def sanitize_host_text(value: str) -> str:
    text = display_path(value)
    text = re.sub(r'"Apple Development: [^"]+"', '"Apple Development: <redacted>"', text)
    text = re.sub(
        r"Apple Development: [^;:]+ \([^)]+\)",
        "Apple Development: <redacted>",
        text,
    )
    text = re.sub(
        r'matched private key label: "[^"]+"',
        'matched private key label: "<redacted>"',
        text,
    )
    return text


def sanitized_rows(rows: list[list[object]]) -> list[list[object]]:
    return [[sanitize_host_text(value) if isinstance(value, str) else value for value in row] for row in rows]


def private_key_label_for_identity(identity_name: str) -> str:
    login_keychain = Path.home() / "Library/Keychains/login.keychain-db"
    if not login_keychain.is_file():
        return ""

    code, cert_output = command_result(
        ["/usr/bin/security", "find-certificate", "-c", identity_name, "-Z", str(login_keychain)]
    )
    if code != 0:
        return ""

    key_hash_match = re.search(r'"skid"<blob>=0x([0-9A-Fa-f]+)', cert_output)
    if not key_hash_match:
        key_hash_match = re.search(r'"hpky"<blob>=0x([0-9A-Fa-f]+)', cert_output)
    if not key_hash_match:
        return ""
    key_hash = key_hash_match.group(1).upper()

    code, keychain_dump = command_result(["/usr/bin/security", "dump-keychain", str(login_keychain)])
    if code != 0:
        return ""

    for item in re.split(r"(?=keychain: )", keychain_dump):
        if "class: 0x00000010" not in item:
            continue
        item_hash_match = re.search(r"0x00000006 <blob>=0x([0-9A-Fa-f]+)", item)
        if not item_hash_match or item_hash_match.group(1).upper() != key_hash:
            continue
        label_match = re.search(r'0x00000001 <blob>="([^"]*)"', item)
        if label_match:
            return label_match.group(1)
    return ""


def team_identifier(app_path: Path) -> str:
    if not app_path.is_dir():
        return ""
    _, output = command_result(["/usr/bin/codesign", "-dv", str(app_path)])
    for line in output.splitlines():
        if line.startswith("TeamIdentifier="):
            return line.split("=", 1)[1]
    return ""


def code_signing_identity_status() -> tuple[str, str]:
    code, output = command_result(["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"])
    if code != 0:
        return "Blocked", f"security find-identity failed: {one_line(output)}"

    identity_records = []
    for line in output.splitlines():
        match = re.match(r'\s*\d+\)\s+([0-9A-Fa-f]+)\s+"([^"]+)"', line)
        if match:
            line_display = one_line(line).replace(match.group(1), "<codesign-identity-hash>", 1)
            identity_records.append((match.group(1), match.group(2), sanitize_host_text(line_display)))
            continue
        match = re.match(r"\s*\d+\)\s+([0-9A-Fa-f]+)\s+(.+)", line)
        if match:
            line_display = one_line(line).replace(match.group(1), "<codesign-identity-hash>", 1)
            identity_records.append((match.group(1), "", sanitize_host_text(line_display)))
    identity_lines = [line for _, _, line in identity_records]
    match = re.search(r"(\d+)\s+valid identities found", output)
    identity_count = int(match.group(1)) if match else len(identity_lines)
    if identity_count <= 0:
        return "Blocked", "security find-identity -v -p codesigning: 0 valid identities found."

    preview = "; ".join(identity_lines[:5])
    if identity_count > 5:
        preview += f"; ... {identity_count - 5} more"

    identity_hash = identity_records[0][0] if identity_records else "-"
    identity_display = "<codesign-identity-hash>" if identity_records else "-"
    identity_name = identity_records[0][1] if identity_records else ""
    with tempfile.TemporaryDirectory(prefix="bastion-codesign-probe.") as tmpdir:
        probe = Path(tmpdir) / "probe"
        probe.write_text("#!/bin/sh\nexit 0\n")
        probe.chmod(0o755)
        sign_code, sign_output = command_result(
            ["/usr/bin/codesign", "--force", "--sign", identity_hash, "--timestamp=none", str(probe)]
        )
        sign_output = sign_output.replace(str(probe), "<codesign-probe>")
    if sign_code != 0:
        private_key_label = private_key_label_for_identity(identity_name) if identity_name else ""
        private_key_hint = (
            f'; matched private key label: "{private_key_label}"'
            if private_key_label
            else ""
        )
        return (
            "Blocked",
            f"{identity_count} valid code-signing identities found: {preview}; codesign usability probe failed for {identity_display}: {one_line(sign_output)}{private_key_hint}",
        )

    return "Satisfied", f"{identity_count} valid code-signing identities found and codesign usability probe passed with {identity_display}: {preview}"


def signed_app_status(app_path: Path) -> tuple[str, str]:
    if not app_path.is_dir():
        return "Blocked", f"App bundle not found at {app_path}."
    if "DerivedData" in str(app_path):
        return "Blocked", f"App path is under DerivedData: {app_path}."
    info_plist = app_path / "Contents" / "Info.plist"
    if not info_plist.is_file():
        return "Blocked", f"App bundle Info.plist missing at {info_plist}."
    executable = app_path / "Contents" / "MacOS" / "bastion"
    if not executable.is_file() or not os.access(executable, os.X_OK):
        return "Blocked", f"App executable missing or not executable at {executable}."
    code, output = command_result(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app_path)])
    if code != 0:
        return "Blocked", f"codesign verify failed for {app_path}: {one_line(output)}"
    team_id = team_identifier(app_path)
    if not team_id:
        return "Blocked", f"codesign verified {app_path}, but TeamIdentifier was empty."
    return "Satisfied", f"codesign verified {app_path}; TeamIdentifier={team_id}."


def iso_mtime(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat(timespec="seconds")


def newest_app_source_input() -> tuple[Path | None, float]:
    newest_path: Path | None = None
    newest_mtime = 0.0
    for pattern in APP_SOURCE_FRESHNESS_PATTERNS:
        for path in (ROOT.parent).glob(pattern):
            if not path.is_file():
                continue
            mtime = path.stat().st_mtime
            if mtime > newest_mtime:
                newest_mtime = mtime
                newest_path = path
    return newest_path, newest_mtime


def app_source_freshness_status(app_path: Path) -> tuple[str, str]:
    newest_source, newest_source_mtime = newest_app_source_input()
    if newest_source is None:
        return "Blocked", "No app source inputs found for freshness comparison."

    binary_paths = [app_path / relative for relative in APP_RUNTIME_BINARY_RELATIVE_PATHS]
    missing = [path for path in binary_paths if not path.is_file()]
    if missing:
        return "Blocked", "Installed app runtime binaries missing: " + ", ".join(str(path) for path in missing)

    oldest_binary = min(binary_paths, key=lambda path: path.stat().st_mtime)
    if oldest_binary.stat().st_mtime < newest_source_mtime:
        return (
            "Blocked",
            f"Installed app is older than current app source inputs; newest source "
            f"{relative_repo_path(newest_source)} mtime={iso_mtime(newest_source)}, "
            f"oldest runtime binary {oldest_binary} mtime={iso_mtime(oldest_binary)}.",
        )

    return (
        "Satisfied",
        f"Installed app runtime binaries are at least as fresh as app source inputs; newest source "
        f"{relative_repo_path(newest_source)} mtime={iso_mtime(newest_source)}, "
        f"oldest runtime binary {oldest_binary} mtime={iso_mtime(oldest_binary)}.",
    )


def candidate_app_paths(app_path: Path) -> list[Path]:
    paths = [
        app_path,
        DEFAULT_APP_PATH,
        RELEASE_CANDIDATE_APP_PATH,
        SYSTEM_INSTALL_APP_PATH,
    ]
    seen: set[str] = set()
    discovered: list[Path] = []
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        if path.is_dir():
            discovered.append(path)
    return discovered


def candidate_app_summary(app_path: Path) -> tuple[str, str]:
    candidates = candidate_app_paths(app_path)
    if not candidates:
        scanned = ", ".join(
            str(path)
            for path in [
                app_path,
                DEFAULT_APP_PATH,
                RELEASE_CANDIDATE_APP_PATH,
                SYSTEM_INSTALL_APP_PATH,
            ]
        )
        return "Open", f"No app bundle candidates found. Scanned: {scanned}."

    details: list[str] = []
    has_satisfied = False
    for candidate in candidates:
        status, evidence = signed_app_status(candidate)
        has_satisfied = has_satisfied or status == "Satisfied"
        details.append(f"{candidate}: {status} - {evidence}")
    return ("Satisfied" if has_satisfied else "Blocked", "; ".join(details))


def latest_lifecycle_phase_log(evidence_dir: Path, phase: str) -> Path | None:
    matches = sorted(evidence_dir.glob(f"*-{phase}.log")) if evidence_dir.exists() else []
    return matches[-1] if matches else None


def notification_click_proof_status(evidence_dir: Path) -> tuple[str, str, str]:
    log_path = latest_lifecycle_phase_log(evidence_dir, "notification-click")
    if log_path is None:
        return (
            "Open",
            f"BASTION_LIFECYCLE_EVIDENCE_DIR={evidence_dir}; latest notification-click log is missing.",
            "Run the notification-click live-runtime phase from the signed stable app and confirm notification delivery.",
        )

    rel_log = relative_repo_path(log_path.resolve())
    log_text = log_path.read_text(errors="replace")
    phase_completed = "==> Live lifecycle verification complete" in log_text and "FAIL:" not in log_text
    matched_click_route = "Matched click route diagnostic:" in log_text
    events: list[dict[str, object]] = []
    for line in log_text.splitlines():
        if "notification_" not in line or "{" not in line:
            continue
        try:
            payload = json.loads(line[line.find("{") :])
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict) and isinstance(payload.get("event"), str):
            events.append(payload)

    for event in reversed(events):
        event_name = str(event.get("event", ""))
        context = event.get("context")
        context_obj = context if isinstance(context, dict) else {}
        opened = context_obj.get("opened")
        if event_name == "notification_click_local_open" or (
            event_name == "notification_click_relay_result" and opened in {True, "true", "1", 1}
        ):
            if not phase_completed:
                return (
                    "Blocked",
                    f"Latest notification-click log {rel_log} has click-route event {event_name} but did not complete cleanly.",
                    "Rerun the notification-click phase from the signed app.",
                )
            if not matched_click_route:
                return (
                    "Blocked",
                    f"Latest notification-click log {rel_log} has click-route event {event_name} but lacks the matched click route verifier line.",
                    "Rerun the notification-click phase so the shell gate captures click-route evidence.",
                )
            return (
                "Satisfied",
                f"Latest notification-click log {rel_log} delivered the probe notification and exercised the notification click route via event {event_name}.",
                "Keep notification authorization enabled; the click-route probe is terminal-driven and does not require an unlocked desktop.",
            )

    for event in reversed(events):
        event_name = str(event.get("event", ""))
        context = event.get("context")
        context_obj = context if isinstance(context, dict) else {}
        if event_name == "notification_skipped_unauthorized":
            status = context_obj.get("status", "<unknown>")
            settings_path = context_obj.get("settingsPath", "System Settings > Notifications")
            return (
                "Blocked",
                f"Latest notification-click log {rel_log} has {event_name}; authorization status={status}; settingsPath={settings_path}.",
                "Enable Bastion notifications in System Settings, then rerun the notification-click phase.",
            )
        if event_name == "notification_delivered":
            if not phase_completed:
                return (
                    "Blocked",
                    f"Latest notification-click log {rel_log} delivered the probe notification but did not complete cleanly.",
                    "Rerun the notification-click phase with notification authorization enabled.",
                )
            if not matched_click_route:
                return (
                    "Blocked",
                    f"Latest notification-click log {rel_log} delivered the probe notification but lacks notification click-route evidence.",
                    "Rerun the notification-click phase from the signed app so delivery and click-route evidence are captured together.",
                )
            return (
                "Blocked",
                f"Latest notification-click log {rel_log} has a matched click-route verifier line but no parsed notification_click diagnostic event.",
                "Rerun the notification-click phase so the shell gate captures the click-route diagnostic event.",
            )
        if event_name == "notification_delivery_failed":
            return (
                "Blocked",
                f"Latest notification-click log {rel_log} has notification_delivery_failed: {one_line(json.dumps(context_obj, sort_keys=True))}",
                "Repair notification delivery, then rerun the notification-click phase.",
            )
        if event_name == "notification_probe_rate_limited":
            return (
                "Blocked",
                f"Latest notification-click log {rel_log} has notification_probe_rate_limited.",
                "Wait for the probe cooldown, then rerun the notification-click phase.",
            )

    return (
        "Blocked",
        f"Latest notification-click log {rel_log} has no successful notification delivery diagnostic event.",
        "Rerun the notification-click phase with notification authorization enabled and confirm delivery.",
    )


RUNTIME_PREREQ_HEADERS = [
    "Prerequisite",
    "Current status",
    "Observed evidence",
    "Required action",
    "Closure command",
]


def runtime_prerequisite_rows(entries: list[dict[str, object]]) -> list[list[object]]:
    app_path = configured_app_path()
    evidence_dir = configured_lifecycle_evidence_dir()
    runtime_ids = runtime_pending_ids(entries)
    live_blocked_ids = sorted(
        str(row.get("ID", ""))
        for row in entries
        if str(row.get("ID", "")) in LIVE_RUNTIME_BLOCKED_IDS
        and row.get("Test status") == "Blocked in this environment"
    )
    app_status, app_evidence = signed_app_status(app_path)
    freshness_status, freshness_evidence = app_source_freshness_status(app_path)
    candidate_status, candidate_evidence = candidate_app_summary(app_path)
    info_plist = app_path / "Contents" / "Info.plist"
    executable = app_path / "Contents" / "MacOS" / "bastion"

    xcode_select_code, xcode_select_output = command_result(["/usr/bin/xcode-select", "-p"])
    xcode_code, xcode_output = command_result(["/usr/bin/xcodebuild", "-version"])
    xcode_path = one_line(xcode_select_output) if xcode_select_code == 0 else f"xcode-select failed: {one_line(xcode_select_output)}"
    xcode_status = "Satisfied" if xcode_code == 0 else "Blocked in this environment"
    xcode_evidence = f"xcode-select -p: {xcode_path}; xcodebuild -version: {one_line(xcode_output)}"
    identity_status, identity_evidence = code_signing_identity_status()
    seeded_status, seeded_evidence, seeded_required_action = seeded_paired_runtime_status(entries)
    notification_status, notification_evidence, notification_required_action = notification_click_proof_status(evidence_dir)
    installed_app_gate_status = "Satisfied" if app_status == "Satisfied" and freshness_status == "Satisfied" else "Blocked"
    installed_app_gate_evidence = (
        f"Code signature and TeamIdentifier={app_status}; Current-source signed app rebuild={freshness_status}. "
    )

    phase_evidence = []
    for phase in REQUIRED_LIVE_PHASES:
        matches = sorted(evidence_dir.glob(f"*-{phase}.log")) if evidence_dir.exists() else []
        phase_evidence.append(f"{phase}={'present' if matches else 'missing'}")
    phases_status = "Satisfied" if all("present" in item for item in phase_evidence) else "Open"

    return sanitized_rows([
        RUNTIME_PREREQ_HEADERS,
        [
            "Signed stable app bundle",
            "Satisfied" if app_status == "Satisfied" else "Blocked",
            f"BASTION_APP_PATH={display_path(app_path)}; exists={'yes' if app_path.is_dir() else 'no'}; stable_path={'no' if 'DerivedData' in str(app_path) else 'yes'}; Info.plist={'yes' if info_plist.is_file() else 'no'}; executable={'yes' if executable.is_file() and os.access(executable, os.X_OK) else 'no'}.",
            "Install a signed stable app outside DerivedData before collecting runtime evidence.",
            SIGNED_REBUILD_COMMAND,
        ],
        [
            "Code signature and TeamIdentifier",
            app_status,
            app_evidence,
            "Use a signed app bundle with a non-empty TeamIdentifier; ad hoc signatures cannot close the runtime gate.",
            f"{APP_RUNTIME_GATE} --check-prereqs --require-prereqs",
        ],
        [
            "Current-source signed app rebuild",
            freshness_status,
            freshness_evidence,
            "Rebuild and reinstall the signed stable app after app, CLI, entitlement, or project source changes before collecting post-fix runtime evidence.",
            SIGNED_REBUILD_COMMAND,
        ],
        [
            "Discovered app bundle candidates",
            candidate_status,
            candidate_evidence,
            "Repair malformed candidates or install a signed stable app, then set BASTION_APP_PATH to the valid bundle before runtime sweeps.",
            f"{APP_RUNTIME_GATE} --check-prereqs --require-prereqs",
        ],
        [
            "Full Xcode developer directory",
            xcode_status,
            xcode_evidence,
            "Select/install full Xcode for xcodebuild-only checks; installed-app runtime phases still also require the signed stable app.",
            "xcodebuild -version",
        ],
        [
            "Code-signing identities",
            identity_status,
            identity_evidence,
            "Install/import a usable Apple Development or Developer ID identity, run the non-mutating codesign check, then run the keychain ACL repair script so /usr/bin/codesign can use the private key noninteractively before rebuilding signed app artifacts.",
            CODE_SIGNING_CHECK_REPAIR_REBUILD_COMMAND,
        ],
        [
            "Seeded paired-client runtime setup",
            seeded_status,
            seeded_evidence,
            seeded_required_action,
            SEEDED_PAIRED_RUNTIME_GATE,
        ],
        [
            "App Runtime Sweep prerequisite gate",
            installed_app_gate_status,
            installed_app_gate_evidence
            + f"{len(runtime_ids)} app-runtime rows require signed-app evidence: {', '.join(runtime_ids)}",
            "Run the prerequisite gate, then exercise every App Runtime Sweep row and audit evidence with --require-pass.",
            f"{APP_RUNTIME_GATE} --check-prereqs --require-prereqs",
        ],
        [
            "Live Runtime Sweep prerequisite gate",
            installed_app_gate_status,
            installed_app_gate_evidence
            + f"{len(live_blocked_ids)} live-runtime rows require installed-app lifecycle evidence: {', '.join(live_blocked_ids)}",
            "Run the live prerequisite gate, phase commands, lifecycle evidence audit, and row evidence audit.",
            f"{LIVE_RUNTIME_GATE} --check-prereqs --require-prereqs",
        ],
        [
            "Lifecycle phase logs",
            phases_status,
            f"BASTION_LIFECYCLE_EVIDENCE_DIR={display_path(evidence_dir)}; " + "; ".join(phase_evidence),
            "Collect fresh-install, reinstall, post-reboot, post-login, and notification-click logs from the signed stable app.",
            f"{LIVE_RUNTIME_GATE} --audit-evidence",
        ],
        [
            "Notification delivery and route proof",
            notification_status,
            notification_evidence,
            notification_required_action,
            f"{LIVE_RUNTIME_GATE} --run-phase notification-click --require-notification-click",
        ],
        [
            "Final completion gate",
            completion_audit_status(entries),
            "python3 qa/audit_goal_completion.py --require-complete remains the strict closure gate.",
            "Close every app-runtime and live-runtime row with pass evidence, then rerun the strict completion audit.",
            "python3 qa/audit_goal_completion.py --require-complete",
        ],
    ])


def seeded_paired_runtime_status(entries: list[dict[str, object]]) -> tuple[str, str, str]:
    evidence_by_id = current_runtime_evidence_by_id(CURRENT_APP_RUNTIME_EVIDENCE)
    queued_seeded_ids = set(runtime_pending_ids(entries)) & SEEDED_PAIRED_RUNTIME_IDS
    pending_seeded_ids = sorted(
        row_id
        for row_id in queued_seeded_ids
        if evidence_by_id.get(row_id, {}).get("Result") != "pass"
    )
    seeded_blocked = sorted(
        row_id
        for row_id, item in evidence_by_id.items()
        if row_id in queued_seeded_ids
        if "Seeded paired-runtime closure attempt also blocked" in item.get("Errors", "")
        or "Seeded paired-runtime closure attempt blocked" in item.get("Errors", "")
        or str(SEEDED_PAIRED_RUNTIME_BLOCKER.relative_to(ROOT.parent)) in item.get("Evidence", "")
    )
    affected_ids = sorted(set(pending_seeded_ids) | set(seeded_blocked))
    blocker_rel = (
        str(SEEDED_PAIRED_RUNTIME_BLOCKER.relative_to(ROOT.parent))
        if SEEDED_PAIRED_RUNTIME_BLOCKER.exists()
        else str(SEEDED_PAIRED_RUNTIME_BLOCKER)
    )
    if not affected_ids:
        return (
            "Satisfied",
            "All seeded paired-client target rows in current app-runtime evidence are pass.",
            "Keep paired-client runtime evidence current when signing/read rows are reopened.",
        )
    if SEEDED_PAIRED_RUNTIME_BLOCKER.exists():
        blocker_text = one_line(SEEDED_PAIRED_RUNTIME_BLOCKER.read_text(errors="replace"))
        evidence = (
            f"{len(affected_ids)} seeded paired-client target rows are not pass or cite seeded setup blockers: "
            f"{', '.join(affected_ids)}. Artifact: {blocker_rel}. {blocker_text[:900]}"
        )
    else:
        evidence = (
            f"{len(affected_ids)} seeded paired-client target rows are not pass: "
            f"{', '.join(affected_ids)}. Blocker artifact is missing: {blocker_rel}."
        )
    return (
        "Blocked",
        evidence,
        "Run the non-mutating codesign check, unlock/grant noninteractive access to the Apple Development signing identity, then run the reversible seeded paired-client gate; or use native UI access to accept a live pairing prompt.",
    )


def completion_blockers(entries: list[dict[str, object]]) -> list[str]:
    test_statuses = Counter(str(row.get("Test status", "")) for row in entries)
    runtime_ids = runtime_pending_ids(entries)
    non_pass_rows = [str(row.get("ID", "")) for row in entries if row.get("Test status") != "Pass"]
    blocked_live_rows = [row_id for row_id in sorted(LIVE_RUNTIME_BLOCKED_IDS) if row_id in non_pass_rows]

    blockers: list[str] = []
    if non_pass_rows:
        blockers.append(
            "non-pass tracker rows remain: "
            + ", ".join(non_pass_rows)
            + f" ({dict(test_statuses)})"
        )
    if runtime_ids:
        blockers.append(
            "signed-app app-runtime user-story rows still require runtime evidence: "
            + ", ".join(runtime_ids)
        )
    if blocked_live_rows:
        blockers.append(
            "signed-app live-runtime rows still require installed-app lifecycle evidence: "
            + ", ".join(blocked_live_rows)
        )
    return blockers


def completion_audit_status(entries: list[dict[str, object]]) -> str:
    return "Complete" if not completion_blockers(entries) else "Not complete"


def summary_rows(entries: list[dict[str, object]]) -> list[list[object]]:
    test_statuses = Counter(str(row.get("Test status", "")) for row in entries)
    feature_statuses = Counter(str(row.get("Feature status", "")) for row in entries)
    runtime_ids = runtime_pending_ids(entries)
    coverage_files = code_coverage_files()
    unmapped_coverage_files = unmapped_code_coverage_files(entries)
    error_states = Counter(row[3] for row in error_ledger_rows(entries)[1:])
    blockers = completion_blockers(entries)

    return [
        ["Metric", "Value", "Notes"],
        ["Total tracker rows", len(entries), "Canonical feature/user-story rows in qa/feature_status_source.json."],
        ["Passing rows", test_statuses["Pass"], "Rows with Test status = Pass."],
        ["Environment-blocked rows", test_statuses["Blocked in this environment"], "Rows blocked by signed-app live runtime prerequisites; full-Xcode availability is recorded separately in Runtime Prereqs."],
        ["Static-inspection-only rows", test_statuses["Pass by static inspection"], "Must stay at 0 before completion."],
        ["Pending rows", test_statuses["Pending"], "Must stay at 0 before completion."],
        ["App-runtime pending rows", len(runtime_ids), "Rows covered by qa/run_app_runtime_user_story_checks.sh signed-app evidence template."],
        ["Feature code files", len(coverage_files), "Source files under BastionShared, bastion, bastion-cli, mcp/src, and scripts covered by the Code Coverage worksheet."],
        ["Unmapped feature code files", len(unmapped_coverage_files), "Must be 0; qa/build_feature_status.py rejects unmapped feature-code files."],
        ["Open failure ledger rows", error_states["Open failure"], "Rows in Error Ledger that have failed and still require a fix."],
        ["Runtime evidence pending ledger rows", error_states["Runtime evidence pending"], "Rows in Error Ledger that still need signed-app runtime evidence."],
        ["Implemented features", feature_statuses["Implemented"], "Rows with Feature status = Implemented."],
        ["Deferred UI features", feature_statuses["Deferred from UI"], "Rows intentionally hidden until real UI management exists."],
        ["Display-only management deferred", feature_statuses["Implemented for display; management deferred"], "Rows where display is implemented but management actions remain deferred."],
        ["Deterministic test summary", deterministic_test_count(), "Expected Swift Testing summary asserted by qa/run_available_checks.sh."],
        ["Live-runtime blocked IDs", ", ".join(sorted(LIVE_RUNTIME_BLOCKED_IDS)), "Rows gated by qa/run_live_runtime_checks.sh."],
        ["Live-runtime gate", LIVE_RUNTIME_GATE, "Use --run-phase commands to create signed-app lifecycle evidence."],
        ["App-runtime gate", APP_RUNTIME_GATE, "Use --write-template to create row-specific signed-app runtime evidence."],
        ["Closure checklist", "Closure Checklist", "Derived worksheet listing the remaining runtime, fix, and retest closure steps."],
        ["Completion audit sheet", "Completion Audit", "Requirement-level audit of the original objective and remaining proof gaps."],
        ["Runtime prerequisites sheet", "Runtime Prereqs", "Current host prerequisite audit for signed-app and live-runtime closure."],
        ["Open issues sheet", "Open Issues", "Derived worksheet consolidating runtime evidence gaps and prerequisite blockers."],
        ["Code coverage sheet", CODE_COVERAGE_SHEET, "Derived worksheet mapping feature-code files to canonical tracker row IDs."],
        ["Test matrix sheet", TEST_MATRIX_SHEET, "Derived worksheet listing every user story's current test lane, error/fix/retest state, and next proof."],
        ["Error ledger sheet", ERROR_LEDGER_SHEET, "Derived worksheet showing every row's current error state, fix status, retest status, closure requirement, and evidence gate."],
        ["Completion audit", completion_audit_status(entries), "Run python3 qa/audit_goal_completion.py --require-complete. " + ("; ".join(blockers) if blockers else "All rows are fully closed.")],
    ]


RUNTIME_SWEEP_HEADERS = [
    "ID",
    "Surface",
    "Feature",
    "User story",
    "Expected behaviour",
    "Test instructions",
    "Result",
    "Evidence",
    "Errors",
]


def current_runtime_evidence_by_id(path: Path) -> dict[str, dict[str, str]]:
    if not path.is_file():
        return {}
    try:
        rows = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(rows, list):
        return {}

    evidence_by_id: dict[str, dict[str, str]] = {}
    required = {"ID", "Result", "Evidence", "Errors"}
    for item in rows:
        if not isinstance(item, dict) or not required <= set(item):
            continue
        row_id = item.get("ID")
        result = item.get("Result")
        evidence = item.get("Evidence")
        errors = item.get("Errors")
        if (
            isinstance(row_id, str)
            and isinstance(result, str)
            and result in RUNTIME_RESULT_VALUES
            and isinstance(evidence, str)
            and isinstance(errors, str)
        ):
            evidence_by_id[row_id] = {
                "Result": result,
                "Evidence": evidence,
                "Errors": errors,
            }
    return evidence_by_id


def runtime_review_summary(row_id: str, evidence_by_id: dict[str, dict[str, str]]) -> str:
    item = evidence_by_id.get(row_id)
    if not item:
        return ""
    result = item["Result"]
    evidence = item["Evidence"]
    errors = item["Errors"]
    parts = [f"Current review artifact result={result}."]
    if errors:
        parts.append(f"Errors/blocker: {errors}")
    if evidence:
        parts.append(f"Evidence: {evidence}")
    return sanitize_host_text(" ".join(parts))


def runtime_sweep_rows_from_template(
    template: list[dict[str, object]], evidence_by_id: dict[str, dict[str, str]]
) -> list[list[object]]:
    rows: list[list[object]] = [RUNTIME_SWEEP_HEADERS]
    for item in template:
        hydrated = dict(item)
        row_id = str(hydrated.get("ID", ""))
        evidence = evidence_by_id.get(row_id)
        if evidence:
            hydrated.update(evidence)
        rows.append([hydrated.get(header, "") for header in RUNTIME_SWEEP_HEADERS])
    return sanitized_rows(rows)


def app_runtime_sweep_rows(entries: list[dict[str, object]]) -> list[list[object]]:
    return runtime_sweep_rows_from_template(
        runtime_evidence_template(entries),
        current_runtime_evidence_by_id(CURRENT_APP_RUNTIME_EVIDENCE),
    )


def live_runtime_sweep_rows(entries: list[dict[str, object]]) -> list[list[object]]:
    return runtime_sweep_rows_from_template(
        live_runtime_evidence_template(entries),
        current_runtime_evidence_by_id(CURRENT_LIVE_RUNTIME_EVIDENCE),
    )


OPEN_ISSUES_HEADERS = [
    "Issue type",
    "ID",
    "Feature or prerequisite",
    "Current state",
    "Required action",
    "Retest proof",
]


def open_issue_rows(entries: list[dict[str, object]]) -> list[list[object]]:
    rows: list[list[object]] = [OPEN_ISSUES_HEADERS]
    app_runtime_evidence = current_runtime_evidence_by_id(CURRENT_APP_RUNTIME_EVIDENCE)
    live_runtime_evidence = current_runtime_evidence_by_id(CURRENT_LIVE_RUNTIME_EVIDENCE)

    for item in runtime_pending_rows(entries):
        row_id = str(item.get("ID", ""))
        feature = str(item.get("Feature", ""))
        surface = str(item.get("Surface", ""))
        current_review = runtime_review_summary(row_id, app_runtime_evidence)
        rows.append(
            [
                "App-runtime evidence missing",
                row_id,
                feature,
                current_review
                or f"{surface} / {feature} still needs signed-app runtime evidence.",
                "Exercise this user story in the signed stable app, document any fail/blocked result in Errors, fix logistical or UX defects, and rerun the app-runtime evidence audit.",
                f"{APP_RUNTIME_GATE} --audit-evidence dist/app-runtime-evidence.json --require-pass; updated source removes {row_id} from App Runtime Sweep.",
            ]
        )

    by_id = {str(row.get("ID", "")): row for row in entries}
    for row_id in sorted(LIVE_RUNTIME_BLOCKED_IDS):
        item = by_id.get(row_id)
        if not item or item.get("Test status") == "Pass":
            continue
        feature = str(item.get("Feature", ""))
        current_review = runtime_review_summary(row_id, live_runtime_evidence)
        rows.append(
            [
                "Live-runtime evidence missing",
                row_id,
                feature,
                current_review
                or f"{row_id} remains Blocked in this environment pending installed-app lifecycle evidence.",
                "Run the live runtime phase commands, collect lifecycle logs, document failures, fix defects, and audit row evidence.",
                f"{LIVE_RUNTIME_GATE} --audit-row-evidence dist/live-runtime-evidence.json --require-pass; updated source sets {row_id} to Pass.",
            ]
        )

    for prereq in runtime_prerequisite_rows(entries)[1:]:
        name = str(prereq[0])
        status = str(prereq[1])
        if status in {"Satisfied", "Complete"}:
            continue
        rows.append(
            [
                "Runtime prerequisite blocker",
                "",
                name,
                str(prereq[2]),
                str(prereq[3]),
                str(prereq[4]),
            ]
        )

    if len(rows) == 1:
        rows.append(
            [
                "None",
                "",
                "No open issues",
                "All runtime evidence and prerequisites are closed.",
                "Keep the canonical tracker and deterministic gate green.",
                "python3 qa/audit_goal_completion.py --require-complete",
            ]
        )

    return sanitized_rows(rows)


CODE_COVERAGE_HEADERS = [
    "Source file",
    "Area",
    "Tracker IDs",
    "Mapped features",
    "Coverage status",
    "Evidence note",
]


def code_coverage_rows(entries: list[dict[str, object]]) -> list[list[object]]:
    rows: list[list[object]] = [CODE_COVERAGE_HEADERS]
    rows_by_file = referenced_rows_by_file(entries)

    for repo_path in sorted(code_coverage_files()):
        mapped_rows = rows_by_file.get(repo_path, [])
        ids = [str(row.get("ID", "")) for row in mapped_rows]
        features = [
            f"{row.get('ID', '')}: {row.get('Feature', '')}"
            for row in mapped_rows
        ]
        if mapped_rows:
            coverage_status = "Mapped to tracker"
            evidence_note = "Direct repository-file evidence reference in qa/feature_status_source.json."
        else:
            coverage_status = "Missing tracker mapping"
            evidence_note = "Add this file to the Code evidence for the user-story row that owns the behaviour."

        rows.append(
            [
                repo_path,
                code_area(repo_path),
                ", ".join(ids),
                "; ".join(features),
                coverage_status,
                evidence_note,
            ]
        )

    if len(rows) == 1:
        rows.append(
            [
                "None",
                "",
                "",
                "",
                "No source files found",
                "No files matched the configured code coverage roots.",
            ]
        )

    return rows


TEST_MATRIX_HEADERS = [
    "ID",
    "Surface",
    "Feature",
    "Test lane",
    "Current result",
    "Errors documented",
    "Fix status",
    "Retest status",
    "Next proof",
]


def test_lane(row: dict[str, object], app_runtime_ids: set[str]) -> str:
    row_id = str(row.get("ID", ""))
    if row_id in app_runtime_ids:
        return "App Runtime Sweep"
    if row_id in LIVE_RUNTIME_BLOCKED_IDS and row.get("Test status") != "Pass":
        return "Live Runtime Sweep"
    if row.get("Test status") == "Pending":
        return "Post-fix retest"
    return "Available deterministic gate"


def test_matrix_next_proof(
    row: dict[str, object],
    lane: str,
    app_runtime_evidence: dict[str, dict[str, str]] | None = None,
    live_runtime_evidence: dict[str, dict[str, str]] | None = None,
) -> str:
    row_id = str(row.get("ID", ""))
    feature = str(row.get("Feature", ""))
    if lane == "App Runtime Sweep":
        current_review = runtime_review_summary(row_id, app_runtime_evidence or {})
        prefix = f"{current_review} " if current_review else ""
        return (
            f"{prefix}Exercise {row_id} {feature} in the signed stable app, record Result/Evidence/Errors in "
            "dist/app-runtime-evidence.json, fix any failure, then run "
            f"{APP_RUNTIME_GATE} --audit-evidence dist/app-runtime-evidence.json --require-pass."
        )
    if lane == "Live Runtime Sweep":
        current_review = runtime_review_summary(row_id, live_runtime_evidence or {})
        prefix = f"{current_review} " if current_review else ""
        return (
            f"{prefix}Collect installed-app lifecycle evidence for {row_id} {feature}, record row evidence in "
            "dist/live-runtime-evidence.json, fix any lifecycle defect, then run "
            f"{LIVE_RUNTIME_GATE} --audit-row-evidence dist/live-runtime-evidence.json --require-pass."
        )
    if lane == "Post-fix retest":
        return (
            f"Implement the pending fix for {row_id} {feature}, document the fix in Fix status, and retest "
            "until Test status is Pass with post-fix evidence."
        )
    return "Keep bash qa/run_available_checks.sh green; rerun after any source, tracker, or workflow change."


def test_matrix_rows(entries: list[dict[str, object]]) -> list[list[object]]:
    rows: list[list[object]] = [TEST_MATRIX_HEADERS]
    app_runtime_ids = set(runtime_pending_ids(entries))
    app_runtime_evidence = current_runtime_evidence_by_id(CURRENT_APP_RUNTIME_EVIDENCE)
    live_runtime_evidence = current_runtime_evidence_by_id(CURRENT_LIVE_RUNTIME_EVIDENCE)
    for item in entries:
        lane = test_lane(item, app_runtime_ids)
        rows.append(
            [
                str(item.get("ID", "")),
                str(item.get("Surface", "")),
                str(item.get("Feature", "")),
                lane,
                str(item.get("Test status", "")),
                str(item.get("Errors documented", "")),
                str(item.get("Fix status", "")),
                str(item.get("Retest status", "")),
                test_matrix_next_proof(item, lane, app_runtime_evidence, live_runtime_evidence),
            ]
        )
    return rows


ERROR_LEDGER_HEADERS = [
    "ID",
    "Surface",
    "Feature",
    "Error state",
    "Errors documented",
    "Fix status",
    "Retest status",
    "Closure requirement",
    "Evidence gate",
]


def error_state(row: dict[str, object], app_runtime_ids: set[str]) -> str:
    row_id = str(row.get("ID", ""))
    if row.get("Test status") == "Pending":
        return "Open failure"
    if row_id in LIVE_RUNTIME_BLOCKED_IDS and row.get("Test status") != "Pass":
        return "Runtime environment blocked"
    if row_id in app_runtime_ids:
        return "Runtime evidence pending"
    return "No open error"


def error_closure_requirement(row: dict[str, object], state: str) -> str:
    row_id = str(row.get("ID", ""))
    feature = str(row.get("Feature", ""))
    if state == "Open failure":
        return f"Fix the documented failure for {row_id} {feature}, update Fix status, and retest until Test status is Pass."
    if state == "Runtime environment blocked":
        return f"Collect signed installed-app lifecycle evidence for {row_id} {feature}; document any runtime failures, fix them, and retest with live-runtime require-pass."
    if state == "Runtime evidence pending":
        return f"Exercise {row_id} {feature} in the signed stable app; document fail/blocked Results in Errors, fix defects, and retest with app-runtime require-pass."
    return "No open error in the canonical tracker; keep deterministic and runtime closure gates green after changes."


def error_evidence_gate(state: str) -> str:
    if state == "Runtime evidence pending":
        return f"{APP_RUNTIME_GATE} --audit-evidence dist/app-runtime-evidence.json --require-pass"
    if state == "Runtime environment blocked":
        return f"{LIVE_RUNTIME_GATE} --audit-row-evidence dist/live-runtime-evidence.json --require-pass"
    if state == "Open failure":
        return "bash qa/run_available_checks.sh plus the relevant runtime evidence audit"
    return "bash qa/run_available_checks.sh"


def error_ledger_rows(entries: list[dict[str, object]]) -> list[list[object]]:
    rows: list[list[object]] = [ERROR_LEDGER_HEADERS]
    app_runtime_ids = set(runtime_pending_ids(entries))
    app_runtime_evidence = current_runtime_evidence_by_id(CURRENT_APP_RUNTIME_EVIDENCE)
    live_runtime_evidence = current_runtime_evidence_by_id(CURRENT_LIVE_RUNTIME_EVIDENCE)
    for item in entries:
        state = error_state(item, app_runtime_ids)
        row_id = str(item.get("ID", ""))
        current_review = ""
        if state == "Runtime evidence pending":
            current_review = runtime_review_summary(row_id, app_runtime_evidence)
        elif state == "Runtime environment blocked":
            current_review = runtime_review_summary(row_id, live_runtime_evidence)
        rows.append(
            [
                row_id,
                str(item.get("Surface", "")),
                str(item.get("Feature", "")),
                state,
                current_review or str(item.get("Errors documented", "")),
                str(item.get("Fix status", "")),
                str(item.get("Retest status", "")),
                error_closure_requirement(item, state),
                error_evidence_gate(state),
            ]
        )
    return rows


def runtime_prerequisite_blocker_names(entries: list[dict[str, object]]) -> list[str]:
    blockers: list[str] = []
    for prereq in runtime_prerequisite_rows(entries)[1:]:
        name = str(prereq[0])
        status = str(prereq[1])
        if name == "Final completion gate":
            continue
        if status not in {"Satisfied", "Complete"}:
            blockers.append(f"{name}={status}")
    return blockers


CLOSURE_CHECKLIST_HEADERS = [
    "Step",
    "Scope",
    "Current state",
    "Required action",
    "Completion proof",
]


def closure_checklist_rows(entries: list[dict[str, object]]) -> list[list[object]]:
    test_statuses = Counter(str(row.get("Test status", "")) for row in entries)
    runtime_ids = runtime_pending_ids(entries)
    live_blocked_ids = sorted(
        str(row.get("ID", ""))
        for row in entries
        if str(row.get("ID", "")) in LIVE_RUNTIME_BLOCKED_IDS
        and row.get("Test status") == "Blocked in this environment"
    )
    pending_ids = [str(row.get("ID", "")) for row in entries if row.get("Test status") == "Pending"]

    app_runtime_state = (
        f"{len(runtime_ids)} signed-app runtime rows remain: {', '.join(runtime_ids)}"
        if runtime_ids
        else "Closed: no app-runtime pending rows remain."
    )
    live_runtime_state = (
        f"{len(live_blocked_ids)} live-runtime rows remain blocked: {', '.join(live_blocked_ids)}"
        if live_blocked_ids
        else "Closed: no live-runtime blocked rows remain."
    )
    pending_state = (
        f"{len(pending_ids)} Pending rows: {', '.join(pending_ids)}"
        if pending_ids
        else "0 Pending rows."
    )
    prereq_blockers = runtime_prerequisite_blocker_names(entries)
    external_prereq_state = (
        "Blocked runtime prerequisites: " + "; ".join(prereq_blockers)
        if prereq_blockers
        else "Runtime prerequisites currently satisfied."
    )

    return [
        CLOSURE_CHECKLIST_HEADERS,
        [
            "1",
            "Canonical tracker and deterministic gates",
            f"{len(entries)} feature rows; {test_statuses['Pass']} Pass; {test_statuses['Blocked in this environment']} Blocked in this environment; {test_statuses['Pending']} Pending.",
            "Run bash qa/run_available_checks.sh after every tracker or code change.",
            "The log ends with Available checks passed, workbook sheets match source, and no legacy tracker exists.",
        ],
        [
            "2",
            "App Runtime Sweep",
            app_runtime_state,
            "Generate dist/app-runtime-evidence.json, exercise every App Runtime Sweep row in the signed stable app, audit evidence, write review artifacts, fix failures, and rerun with --require-pass.",
            "All app-runtime evidence rows are pass, qa/run_app_runtime_user_story_checks.sh --audit-evidence ... --require-pass succeeds, and updated source validates with 0 app-runtime pending rows.",
        ],
        [
            "3",
            "Live Runtime Sweep",
            live_runtime_state,
            "Run the Live Runtime Sweep phase commands against a signed stable app and full runtime environment, then audit row evidence with --require-pass.",
            "All live-runtime evidence rows are pass, qa/run_live_runtime_checks.sh --audit-row-evidence ... --require-pass succeeds, and updated source validates with 0 blocked live rows.",
        ],
        [
            "4",
            "Error, fix, and retest loop",
            f"{pending_state} {test_statuses['Pass by static inspection']} Pass by static inspection rows.",
            "For fail or blocked runtime evidence, update Errors documented, Fix status, and Retest status, fix logistical or UX defects, rebuild the workbook, and retest the affected behaviour.",
            "Pending rows = 0, Pass by static inspection rows = 0, and every runtime/live row is closed with post-fix pass evidence.",
        ],
        [
            "5",
            "External runtime prerequisites",
            external_prereq_state,
            "Run scripts/dev-enable-codesign-keychain-access.sh if codesign cannot use the private key, rebuild with scripts/dev-rebuild-signed.sh, enable Bastion notifications for the notification-click phase, then rerun both runtime prerequisite gates with --require-prereqs.",
            "Runtime prereq gates pass, Code-signing identities and Notification delivery and route proof are Satisfied, lifecycle phase logs audit cleanly, and final app/live runtime evidence audits pass with --require-pass.",
        ],
    ]


COMPLETION_AUDIT_HEADERS = [
    "Objective requirement",
    "Current status",
    "Authoritative evidence",
    "Remaining proof needed",
]


def completion_audit_rows(entries: list[dict[str, object]]) -> list[list[object]]:
    runtime_ids = runtime_pending_ids(entries)
    live_blocked_ids = sorted(
        str(row.get("ID", ""))
        for row in entries
        if str(row.get("ID", "")) in LIVE_RUNTIME_BLOCKED_IDS
        and row.get("Test status") == "Blocked in this environment"
    )
    pending_ids = [str(row.get("ID", "")) for row in entries if row.get("Test status") == "Pending"]
    blockers = completion_blockers(entries)
    runtime_status = "Open" if runtime_ids or live_blocked_ids else "Proven"
    fix_status = "Open" if runtime_ids or live_blocked_ids or pending_ids else "Proven"
    completion_status = "Open" if blockers else "Proven"

    return [
        COMPLETION_AUDIT_HEADERS,
        [
            "Every app feature is mapped to a user story and expected behaviour",
            "Proven",
            f"{len(entries)} canonical rows in qa/feature_status_source.json; builder validates required fields, canonical IDs/statuses/surfaces, code references, app Swift evidence coverage, and selected feature-code coverage exposed in the {CODE_COVERAGE_SHEET} worksheet.",
            "Keep qa/build_feature_status.py and qa/run_available_checks.sh green after any feature/source change.",
        ],
        [
            "Single canonical spreadsheet tracks feature status",
            "Proven",
            "qa/feature_status.xlsx is generated from qa/feature_status_source.json; qa/run_available_checks.sh rejects legacy docs/feature_user_story_tracker.csv and verifies workbook sheets.",
            "Continue using qa/feature_status_source.json plus python3 qa/build_feature_status.py as the only tracker update path.",
        ],
        [
            "Test every user story and document all errors",
            runtime_status,
            f"Available deterministic gate covers static/testable behaviour; Test Matrix lists every row's current lane and next proof; Runtime Prereqs records host blockers; {len(runtime_ids)} app-runtime rows and {len(live_blocked_ids)} live-runtime rows still require signed-app evidence.",
            "Satisfy Runtime Prereqs, then run App Runtime Sweep and Live Runtime Sweep evidence audits with real signed-app artifacts; document fail/blocked rows in Errors documented.",
        ],
        [
            "Fix every logistical or UX error found by runtime testing",
            fix_status,
            f"{len(pending_ids)} tracker rows are currently Pending; Error Ledger exposes every row's Errors documented, Fix status, Retest status, closure requirement, and evidence gate.",
            "For each runtime failure, implement the fix, rebuild the tracker, and keep deterministic plus runtime evidence audits green.",
        ],
        [
            "Retest every user behaviour after fixes",
            completion_status,
            "qa/audit_goal_completion.py --require-complete is the final strict audit; Summary exposes the same completion state.",
            "All tracker rows must be Pass, app-runtime pending count must be 0, live-runtime blocked rows must be 0, and final app/live evidence audits must pass with --require-pass.",
        ],
    ]


def result_validation(rows: list[list[object]]) -> list[str]:
    if len(rows) <= 1:
        return []
    return [list_validation_xml(f"G2:G{len(rows)}", RUNTIME_RESULT_VALUES)]


def main() -> None:
    entries = validate_entries(json.loads(SOURCE.read_text()))
    rows = [HEADERS]
    for item in entries:
        rows.append([item.get(header, "") for header in HEADERS])
    summary = summary_rows(entries)
    app_runtime = app_runtime_sweep_rows(entries)
    live_runtime = live_runtime_sweep_rows(entries)
    closure = closure_checklist_rows(entries)
    completion = completion_audit_rows(entries)
    runtime_prereqs = runtime_prerequisite_rows(entries)
    open_issues = open_issue_rows(entries)
    code_coverage = code_coverage_rows(entries)
    test_matrix = test_matrix_rows(entries)
    error_ledger = error_ledger_rows(entries)
    feature_validations = [
        list_validation_xml(f"G2:G{len(rows)}", FEATURE_STATUS_VALUES),
        list_validation_xml(f"H2:H{len(rows)}", TEST_STATUS_VALUES),
    ]

    widths = [12, 16, 28, 48, 58, 42, 18, 18, 42, 42, 18, 18, 36]
    summary_widths = [34, 24, 92]
    runtime_sweep_widths = [12, 16, 28, 48, 58, 76, 14, 48, 42]
    live_runtime_widths = [12, 18, 34, 48, 58, 88, 14, 48, 42]
    closure_widths = [10, 32, 68, 84, 84]
    completion_widths = [42, 18, 84, 84]
    runtime_prereq_widths = [34, 24, 78, 78, 58]
    open_issue_widths = [30, 12, 34, 72, 82, 72]
    code_coverage_widths = [58, 22, 28, 82, 24, 78]
    test_matrix_widths = [12, 18, 34, 24, 18, 58, 36, 58, 82]
    error_ledger_widths = [12, 18, 34, 28, 58, 36, 58, 82, 72]
    with zipfile.ZipFile(OUTPUT, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml())
        zf.writestr("_rels/.rels", rels_xml())
        zf.writestr("xl/workbook.xml", workbook_xml())
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml())
        zf.writestr("xl/styles.xml", styles_xml())
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml(rows, widths, feature_validations))
        zf.writestr("xl/worksheets/sheet2.xml", sheet_xml(summary, summary_widths))
        zf.writestr("xl/worksheets/sheet3.xml", sheet_xml(app_runtime, runtime_sweep_widths, result_validation(app_runtime)))
        zf.writestr("xl/worksheets/sheet4.xml", sheet_xml(live_runtime, live_runtime_widths, result_validation(live_runtime)))
        zf.writestr("xl/worksheets/sheet5.xml", sheet_xml(closure, closure_widths))
        zf.writestr("xl/worksheets/sheet6.xml", sheet_xml(completion, completion_widths))
        zf.writestr("xl/worksheets/sheet7.xml", sheet_xml(runtime_prereqs, runtime_prereq_widths))
        zf.writestr("xl/worksheets/sheet8.xml", sheet_xml(open_issues, open_issue_widths))
        zf.writestr("xl/worksheets/sheet9.xml", sheet_xml(code_coverage, code_coverage_widths))
        zf.writestr("xl/worksheets/sheet10.xml", sheet_xml(test_matrix, test_matrix_widths))
        zf.writestr("xl/worksheets/sheet11.xml", sheet_xml(error_ledger, error_ledger_widths))
        zf.writestr("docProps/core.xml", core_xml())
        zf.writestr("docProps/app.xml", app_xml())
    LEGACY_CSV.unlink(missing_ok=True)
    print(OUTPUT)


if __name__ == "__main__":
    main()
