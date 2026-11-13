#!/usr/bin/env python3
"""Export a WinShield scan history report from the SQLite database.

Usage:
    python report.py                       # latest scan + trend, printed as Markdown
    python report.py --out report.md       # write to a file
    python report.py --db C:\\path\\winshield.db --last 20

Uses only the Python standard library.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path


def default_db_path() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    base = Path(local) if local else Path.home() / ".local" / "share"
    return base / "WinShield" / "winshield.db"


def fmt_time(iso: str) -> str:
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso


def escape_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def build_report(conn: sqlite3.Connection, last: int) -> str:
    conn.row_factory = sqlite3.Row

    scans = conn.execute(
        "SELECT id, started_utc, machine_name, score, pass_count, warn_count, fail_count "
        "FROM scans ORDER BY started_utc DESC LIMIT ?",
        (last,),
    ).fetchall()

    if not scans:
        return "# WinShield report\n\nNo scans have been saved yet. Run a scan in the app first.\n"

    latest = scans[0]
    lines: list[str] = []
    lines.append("# WinShield security report")
    lines.append("")
    lines.append(f"- Machine: **{latest['machine_name']}**")
    lines.append(f"- Latest scan: {fmt_time(latest['started_utc'])}")
    lines.append(
        f"- Score: **{latest['score']}/100** "
        f"({latest['pass_count']} passed, {latest['warn_count']} warnings, {latest['fail_count']} failed)"
    )
    lines.append("")

    results = conn.execute(
        "SELECT title, status, detail, recommendation FROM check_results WHERE scan_id = ? ORDER BY id",
        (latest["id"],),
    ).fetchall()

    lines.append("## Latest results")
    lines.append("")
    lines.append("| Status | Check | Detail |")
    lines.append("|---|---|---|")
    for r in results:
        lines.append(f"| {r['status']} | {escape_cell(r['title'])} | {escape_cell(r['detail'])} |")
    lines.append("")

    to_fix = [r for r in results if r["status"] in ("Fail", "Warning")]
    if to_fix:
        lines.append("## What to fix")
        lines.append("")
        for r in sorted(to_fix, key=lambda x: 0 if x["status"] == "Fail" else 1):
            lines.append(f"- **{r['title']}** ({r['status']}): {r['recommendation']}")
        lines.append("")

    lines.append("## Score trend")
    lines.append("")
    lines.append("| Scan time | Score | Pass | Warn | Fail |")
    lines.append("|---|---|---|---|---|")
    for s in scans:
        lines.append(
            f"| {fmt_time(s['started_utc'])} | {s['score']} | {s['pass_count']} | "
            f"{s['warn_count']} | {s['fail_count']} |"
        )
    lines.append("")

    if len(scans) >= 2:
        delta = latest["score"] - scans[1]["score"]
        direction = "up" if delta > 0 else "down" if delta < 0 else "unchanged"
        lines.append(f"Compared with the previous scan the score is {direction}"
                     + (f" by {abs(delta)} points." if delta else "."))
        lines.append("")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export a WinShield scan history report.")
    parser.add_argument("--db", type=Path, default=default_db_path(), help="path to winshield.db")
    parser.add_argument("--last", type=int, default=10, help="how many scans to include in the trend")
    parser.add_argument("--out", type=Path, help="write the report to this file instead of printing it")
    args = parser.parse_args(argv)

    if not args.db.exists():
        print(f"Database not found: {args.db}", file=sys.stderr)
        return 1

    with sqlite3.connect(f"file:{args.db}?mode=ro", uri=True) as conn:
        report = build_report(conn, max(1, args.last))

    if args.out:
        args.out.write_text(report, encoding="utf-8")
        print(f"Report written to {args.out}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
