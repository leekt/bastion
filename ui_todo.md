# Archived UI TODO

This file is intentionally no longer the active UI backlog.

The canonical feature, user-story, expected-behaviour, error, fix, and retest
tracker is:

- `qa/feature_status_source.json`
- `qa/feature_status.xlsx`

The previous contents of this file were an audit snapshot from 2026-05-04. The
remaining valid items were folded into the canonical tracker, and the old P0
items are no longer current in source:

- Audit history no longer exposes an inert saved-view "Save current" action.
- Approval preview controls are gated behind `#if DEBUG`.
- The menu-bar footer no longer exposes a fake "Wallet Groups..." link.

Run `bash qa/run_available_checks.sh` to rebuild and validate the canonical
tracker, including workbook shape, controlled status/surface values, repository
evidence paths, and available deterministic retest gates.
