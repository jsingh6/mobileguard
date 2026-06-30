# Copyright 2026 Jaspreet Singh
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

"""MobileGuard CLI — all commands.

Entry point: mobileguard (registered in pyproject.toml)

Exit codes:
  0  All checks passed / no violations at or above --fail-on level
  1  Violations found at or above --fail-on level
  2  Scan or configuration error (bad path, missing API key, etc.)
"""

from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path
from typing import Any

import click
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from mobileguard import __version__
from mobileguard.models import Finding, ScanResult, Severity

console = Console()
err_console = Console(stderr=True)

_SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.ERROR: "red",
    Severity.WARNING: "yellow",
    Severity.INFO: "blue",
}

_SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.ERROR: "ERROR",
    Severity.WARNING: "WARNING",
    Severity.INFO: "INFO",
}


# ── Root group ────────────────────────────────────────────────────────────────

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="mobileguard")
def cli() -> None:
    """MobileGuard — AI governance for consumer mobile platforms.

    Prevents App Store and Google Play rejections caused by AI-generated code.
    Maps to four governance pillars from arXiv:XXXX.XXXXX:

    \b
      mobileguard scan     — PGSG: detect policy violations before store submission
      mobileguard contract — PDQC: evaluate AI-generated code against a quality contract
      mobileguard audit    — PGSG: generate EU AI Act / App Store compliance report
      mobileguard tier     — TAC-M: check AI agent's current autonomy tier
      mobileguard init     — create a mobileguard.json quality contract

    MobileGuard does not collect telemetry or send analytics.

    \b
    Exit codes:
      0  Pass — no violations at or above the threshold
      1  Fail — violations found
      2  Error — bad path, missing API key, or configuration problem
    """


# ── mobileguard scan ──────────────────────────────────────────────────────────

@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--platform",
    type=click.Choice(["ios", "android", "flutter", "react-native", "auto", "macos"]),
    default="auto",
    show_default=True,
    help="Target platform. 'auto' detects extensions; 'macos' skips macOS warning.",
)
@click.option(
    "--rules",
    default="all",
    show_default=True,
    help="Comma-separated rule categories: app-store,google-play,eu-ai-act,owasp (or 'all').",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "error", "warning", "info"]),
    default="warning",
    show_default=True,
    help="Minimum severity level to report.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "sarif", "markdown"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output",
    type=click.Path(),
    default=None,
    help="Write report to this file instead of stdout.",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(["critical", "error", "warning"]),
    default=None,
    help="Exit 1 if any violation at this severity or above is found.",
)
@click.option(
    "--llm",
    is_flag=True,
    default=False,
    help="Use Claude API for semantic analysis on top of pattern detection (requires --api-key).",
)
@click.option(
    "--api-key",
    default=None,
    envvar="ANTHROPIC_API_KEY",
    help="Anthropic API key. Default: ANTHROPIC_API_KEY environment variable.",
)
def scan(
    path: str,
    platform: str,
    rules: str,
    severity: str,
    output_format: str,
    output: str | None,
    fail_on: str | None,
    llm: bool,
    api_key: str | None,
) -> None:
    """Scan a mobile codebase for governance violations.

    PATH can be a project directory or a single source file. The scanner
    detects the platform automatically from file extensions unless --platform
    is specified.

    \b
    Examples:
      mobileguard scan ./MyApp
      mobileguard scan ./MyApp --platform ios --fail-on critical
      mobileguard scan ./MyApp --format sarif --output results.sarif
      mobileguard scan ./MyApp --rules app-store,owasp --severity error
    """
    if llm and not api_key:
        err_console.print(
            "[red]Error:[/red] --llm requires an Anthropic API key. "
            "Set ANTHROPIC_API_KEY or pass --api-key."
        )
        sys.exit(2)

    from mobileguard.models import Severity as Sev
    from mobileguard.scanner import findings_meet_fail_threshold, run_scan

    min_sev = Sev(severity)
    scanned_files: list[str] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"Scanning {path}...", total=None)

        def _cb(fp: str) -> None:
            scanned_files.append(fp)
            progress.update(task, description=f"Scanning {fp}")

        try:
            result = run_scan(
                path,
                platform=platform,
                rules=rules,
                min_severity=min_sev,
                progress_callback=_cb,
            )
        except Exception as exc:
            progress.stop()
            err_console.print(f"[red]Scan error:[/red] {exc}")
            sys.exit(2)

    rendered = _render_scan(result, output_format, path)

    if output:
        Path(output).write_text(rendered, encoding="utf-8")
        console.print(f"[green]Report written to:[/green] {output}")
    else:
        if output_format == "table":
            _print_table_result(result, path)
        else:
            click.echo(rendered)  # raw output — bypass Rich markup processing

    # Determine exit code
    if fail_on:
        if findings_meet_fail_threshold(result.findings, fail_on):
            sys.exit(1)
    elif not result.passed:
        sys.exit(1)


def _render_scan(result: ScanResult, fmt: str, path: str) -> str:
    """Render a ScanResult to the requested format string."""
    if fmt == "json":
        return result.model_dump_json(indent=2)
    if fmt == "sarif":
        return _render_sarif(result)
    if fmt == "markdown":
        return _render_scan_markdown(result, path)
    return ""  # table is printed directly


def _print_table_result(result: ScanResult, path: str) -> None:
    """Print a rich table scan result to the console."""
    platform_label = result.platform.value.upper()
    duration = result.scan_duration_seconds

    console.print()
    console.print(
        Panel(
            f"[bold]MobileGuard Scan Results[/bold]\n"
            f"Project: [cyan]{Path(path).name}[/cyan] ({platform_label}) · "
            f"{result.files_scanned} file{'s' if result.files_scanned != 1 else ''} scanned · "
            f"{duration}s",
            box=box.DOUBLE_EDGE,
            expand=False,
        )
    )

    for warn in result.warnings:
        console.print(f"\n[yellow]{warn}[/yellow]")

    grouped: dict[Severity, list[Finding]] = {
        Severity.CRITICAL: [],
        Severity.ERROR: [],
        Severity.WARNING: [],
        Severity.INFO: [],
    }
    for f in result.findings:
        grouped[f.severity].append(f)

    for sev in [Severity.CRITICAL, Severity.ERROR, Severity.WARNING, Severity.INFO]:
        findings_at_sev = grouped[sev]
        if not findings_at_sev:
            continue

        style = _SEVERITY_STYLE[sev]
        label = _SEVERITY_LABEL[sev]
        console.print(f"\n[{style}]{label} ({len(findings_at_sev)})[/{style}]")

        for f in findings_at_sev:
            loc = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
            console.print(f"  [{style}]{f.rule_id}[/{style}]  [dim]{loc}[/dim]")
            console.print(f"          {f.description}")
            if f.evidence:
                console.print(f"          [dim]→ {f.evidence[:120]}[/dim]")
            console.print(f"          [green]→ Fix:[/green] {f.fix[:120]}")
            if f.reference:
                console.print(f"          [blue]→ {f.reference}[/blue]")

    c = result.summary
    console.print()
    console.print("─" * 60)
    console.print(
        f"Summary: [bold red]{c['critical']} CRITICAL[/bold red] · "
        f"[red]{c['error']} ERROR[/red] · "
        f"[yellow]{c['warning']} WARNING[/yellow] · "
        f"[blue]{c['info']} INFO[/blue]"
    )

    if result.passed:
        console.print("[bold green]Status: PASS[/bold green]")
    else:
        console.print("[bold red]Status: FAIL (violations found)[/bold red]")
        console.print(
            "Run [cyan]mobileguard audit[/cyan] to generate an EU AI Act compliance report."
        )

    console.print()


def _render_scan_markdown(result: ScanResult, path: str) -> str:
    """Render a ScanResult as Markdown."""
    lines = [
        "# MobileGuard Scan Results",
        f"**Project:** {Path(path).name} ({result.platform.value.upper()}) · "
        f"{result.files_scanned} files scanned · {result.scan_duration_seconds}s",
        "",
    ]
    for warn in result.warnings:
        lines += [f"> **{warn}**", ""]
    grouped: dict[Severity, list[Finding]] = {s: [] for s in Severity}
    for f in result.findings:
        grouped[f.severity].append(f)

    for sev in [Severity.CRITICAL, Severity.ERROR, Severity.WARNING, Severity.INFO]:
        fs = grouped[sev]
        if not fs:
            continue
        lines.append(f"## {sev.value.upper()} ({len(fs)})")
        for f in fs:
            loc = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
            lines += [
                f"### {f.rule_id} — {f.description}",
                f"- **Location:** `{loc}`",
                f"- **Fix:** {f.fix}",
                f"- **Reference:** {f.reference}" if f.reference else "",
                "",
            ]

    c = result.summary
    status = "PASS" if result.passed else "FAIL"
    lines += [
        "---",
        f"**Summary:** {c['critical']} CRITICAL · {c['error']} ERROR · "
        f"{c['warning']} WARNING · {c['info']} INFO",
        f"**Status:** {status}",
    ]
    return "\n".join(lines)


def _render_sarif(result: ScanResult) -> str:
    """Render a ScanResult as SARIF 2.1.0 for GitHub Code Scanning."""
    from mobileguard.rules import ALL_RULES

    sarif_level = {
        Severity.CRITICAL: "error",
        Severity.ERROR: "error",
        Severity.WARNING: "warning",
        Severity.INFO: "note",
    }

    rules_used = {f.rule_id for f in result.findings}
    sarif_rules = []
    for rule_id in sorted(rules_used):
        rule = ALL_RULES.get(rule_id)
        if rule:
            sarif_rules.append(
                {
                    "id": rule.id,
                    "name": rule.id.replace("-", "") + "Violation",
                    "shortDescription": {"text": rule.description},
                    "helpUri": rule.reference,
                    "properties": {"severity": rule.severity.value},
                }
            )

    sarif_results = []
    for f in result.findings:
        loc: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": f.file_path.replace("\\", "/")},
            }
        }
        if f.line_number:
            loc["physicalLocation"]["region"] = {"startLine": f.line_number}

        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": sarif_level[f.severity],
                "message": {"text": f"{f.description}. Fix: {f.fix}"},
                "locations": [loc],
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MobileGuard",
                        "version": __version__,
                        "informationUri": "https://github.com/jsingh6/mobileguard",
                        "rules": sarif_rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


# ── mobileguard contract ──────────────────────────────────────────────────────

@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--contract",
    "contract_path",
    default="mobileguard.json",
    show_default=True,
    help="Path to mobileguard.json quality contract.",
)
@click.option(
    "--stage",
    type=click.Choice(["code-generation", "test-generation", "code-review"]),
    default="code-generation",
    show_default=True,
    help="Pipeline stage being evaluated.",
)
@click.option(
    "--agent",
    "agent_id",
    default="unknown-agent",
    show_default=True,
    help="Identifier of the AI agent that produced this code.",
)
@click.option(
    "--platform",
    type=click.Choice(["ios", "android", "flutter", "react-native"]),
    default=None,
    help="Override platform detection.",
)
@click.option(
    "--api-key",
    default=None,
    envvar="ANTHROPIC_API_KEY",
    help="Anthropic API key. Default: ANTHROPIC_API_KEY environment variable.",
)
@click.option(
    "--fail-fast",
    is_flag=True,
    default=False,
    help="Exit 1 if the pipeline should halt (halt_pipeline=true in verdict).",
)
def contract(
    path: str,
    contract_path: str,
    stage: str,
    agent_id: str,
    platform: str | None,
    api_key: str | None,
    fail_fast: bool,
) -> None:
    """Evaluate AI-generated code against a quality contract (PDQC pillar).

    Calls the Claude API to evaluate output consistency, platform behavioral
    invariants, regression coverage, and security. Results are appended to
    the append-only audit log at .mobileguard/audit/.

    Requires an Anthropic API key (ANTHROPIC_API_KEY env var or --api-key).

    \b
    Examples:
      mobileguard contract ./GeneratedFeature.swift --stage code-generation --agent claude-code
      mobileguard contract ./src/ --stage code-review --agent copilot --platform android
    """
    if not api_key:
        err_console.print(
            "[red]Error:[/red] mobileguard contract requires an Anthropic API key.\n"
            "Set the ANTHROPIC_API_KEY environment variable or pass --api-key."
        )
        sys.exit(2)

    from mobileguard.contract import evaluate, load_contract

    # Surface helpful error for missing contract before calling the API
    try:
        load_contract(contract_path)
    except FileNotFoundError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        sys.exit(2)
    except ValueError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        sys.exit(2)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        progress.add_task("Evaluating with Claude API...", total=None)
        try:
            verdict = evaluate(
                target_path=path,
                contract_path=contract_path,
                stage=stage,
                agent_id=agent_id,
                platform=platform,
                api_key=api_key,
            )
        except FileNotFoundError as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            sys.exit(2)
        except RuntimeError as exc:
            err_console.print(f"[red]API error:[/red] {exc}")
            sys.exit(2)

    # Print verdict
    outcome_style = {
        "PASS": "bold green",
        "WARNING": "bold yellow",
        "FAIL": "bold red",
    }.get(verdict.outcome, "white")

    console.print()
    console.print(
        Panel(
            f"[bold]MobileGuard Contract Evaluation[/bold]\n"
            f"Stage: {verdict.stage} · Agent: {verdict.agent_id} · "
            f"Platform: {verdict.platform.value}",
            box=box.DOUBLE_EDGE,
            expand=False,
        )
    )
    console.print(
        f"\nOverall score: [bold]{verdict.score:.2f}[/bold] / 1.00  "
        f"[{outcome_style}]{verdict.outcome}[/{outcome_style}]"
    )

    if verdict.findings:
        console.print("\nFindings:")
        for f in verdict.findings:
            style = _SEVERITY_STYLE.get(f.severity, "white")
            console.print(f"  [{style}][{f.severity.value.upper()}][/{style}]  {f.description}")
            if f.evidence:
                console.print(f"           [dim]{f.evidence[:120]}[/dim]")
            console.print(f"           [green]→ Fix:[/green] {f.fix[:120]}")

    console.print(f"\n[italic]{verdict.recommendation}[/italic]")

    if verdict.human_override_required:
        console.print(
            "\n[bold yellow]⚠ Human override required to proceed.[/bold yellow] "
            "Override will be logged to audit trail."
        )

    audit_path = f".mobileguard/audit/mobileguard-{verdict.timestamp.strftime('%Y-%m-%d')}.jsonl"
    console.print(f"\n[dim]Logged to: {audit_path}[/dim]")
    console.print()

    if fail_fast and verdict.halt_pipeline:
        sys.exit(1)


# ── mobileguard audit ─────────────────────────────────────────────────────────

@cli.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["markdown", "json", "html"]),
    default="markdown",
    show_default=True,
    help="Output format. PDF export coming in v1.1 — convert HTML using browser print-to-PDF.",
)
@click.option(
    "--output",
    type=click.Path(),
    default="mobileguard-audit-report.md",
    show_default=True,
    help="Path to write the report.",
)
@click.option(
    "--platform",
    type=click.Choice(["ios", "android", "flutter", "react-native", "all"]),
    default="all",
    show_default=True,
    help="Platform(s) to audit.",
)
@click.option("--app-name", default="Unknown App", show_default=True, help="App display name.")
@click.option("--version", "app_version", default="1.0.0", show_default=True, help="App version.")
@click.option(
    "--include-evidence",
    is_flag=True,
    default=False,
    help="Include code snippets as evidence in the report.",
)
def audit(
    path: str,
    output_format: str,
    output: str,
    platform: str,
    app_name: str,
    app_version: str,
    include_evidence: bool,
) -> None:
    """Generate an AI governance compliance report (PGSG + PDQC pillars).

    Scans the codebase and produces a structured report documenting AI governance
    practices against EU AI Act Article 50, Apple Guideline 5.1.2(i), Google Play
    AI Policy, and OWASP Mobile AI Top 5. This is the document to show to legal,
    compliance, or an App Store reviewer.

    \b
    Examples:
      mobileguard audit ./MyApp --app-name "My App" --version "2.0.0"
      mobileguard audit ./MyApp --format html --output report.html
      mobileguard audit ./MyApp --format json --include-evidence
    """
    from mobileguard.audit import generate_report, render_html, render_json, render_markdown
    from mobileguard.models import Platform as Plat
    from mobileguard.scanner import run_scan

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        progress.add_task(f"Scanning {path}...", total=None)
        try:
            scan_result = run_scan(path, platform="auto", rules="all", min_severity=Severity.INFO)
        except Exception as exc:
            err_console.print(f"[red]Scan error:[/red] {exc}")
            sys.exit(2)

    if platform == "all":
        platforms = list(Plat)
    else:
        platforms = [Plat(platform)]

    report = generate_report(
        scan_result,
        app_name=app_name,
        version=app_version,
        platforms=platforms,
        include_evidence=include_evidence,
    )

    if output_format == "markdown":
        content = render_markdown(report)
        out_path = output if output != "mobileguard-audit-report.md" else output
    elif output_format == "html":
        content = render_html(report)
        if output == "mobileguard-audit-report.md":
            out_path = "mobileguard-audit-report.html"
        else:
            out_path = output
    else:
        content = render_json(report)
        if output == "mobileguard-audit-report.md":
            out_path = "mobileguard-audit-report.json"
        else:
            out_path = output

    Path(out_path).write_text(content, encoding="utf-8")

    c = scan_result.summary
    status = "[green]PASS[/green]" if scan_result.passed else "[red]FAIL[/red]"
    console.print(
        f"[green]Audit report written to:[/green] {out_path}\n"
        f"Status: {status} · "
        f"{c['critical']} critical · {c['error']} error · {c['warning']} warning"
    )


# ── mobileguard tier ──────────────────────────────────────────────────────────

@cli.command()
@click.argument("agent_id")
@click.option(
    "--history",
    "audit_dir",
    default=".mobileguard/audit",
    show_default=True,
    help="Path to audit log directory.",
)
@click.option(
    "--contract",
    "contract_path",
    default=None,
    help="Path to mobileguard.json (optional, for max tier override).",
)
@click.option(
    "--cfsr",
    default=None,
    type=float,
    help="Current crash-free session rate as decimal (e.g. 0.997).",
)
def tier(agent_id: str, audit_dir: str, contract_path: str | None, cfsr: float | None) -> None:
    """Show the current TAC-M autonomy tier for an AI agent (TAC-M pillar).

    Reads the agent's quality history from the audit log and computes its
    current tier (L1–L5). Higher tiers permit greater autonomous deployment reach.

    \b
    Examples:
      mobileguard tier my-agent-01
      mobileguard tier claude-code --history ./audit-logs --cfsr 0.997
    """
    from mobileguard.tier import compute_tier, format_history_table

    result = compute_tier(agent_id, audit_dir)

    console.print()
    console.print(
        Panel(
            f"[bold]TAC-M Autonomy Tier Report — {agent_id}[/bold]",
            box=box.DOUBLE_EDGE,
            expand=False,
        )
    )

    reach_pct = int(result.max_deployment_reach * 100)
    console.print(f"\nCurrent tier   : [bold]{result.current_tier}[/bold] — {result.tier_label}")
    console.print(f"Max deployment : {reach_pct}% (bounded by tier)")
    console.print(f"Clean cycles   : {result.consecutive_clean_cycles} consecutive")

    if cfsr is not None:
        cfsr_pct = cfsr * 100
        cfsr_ok = cfsr >= 0.995
        cfsr_style = "green" if cfsr_ok else "red"
        console.print(f"Crash-free rate: [{cfsr_style}]{cfsr_pct:.3f}%[/{cfsr_style}]")

    console.print(f"Next tier      : {result.recommendation}")

    # History table
    history_rows = format_history_table(agent_id, audit_dir, limit=5)
    if history_rows:
        console.print("\nRecent history (last 5 cycles):")
        for row in history_rows:
            note = f"  {row['note']}" if row["note"] else ""
            console.print(
                f"  {row['icon']} {row['date']}  {row['outcome']:7s}  score: {row['score']}{note}"
            )

    if result.demotion_triggered:
        console.print(
            f"\n[bold red]⚠ Demotion trigger active:[/bold red] {result.demotion_reason}"
        )
    else:
        console.print("\n[green]No demotion triggers active.[/green]")

    console.print()


# ── mobileguard init ──────────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--platform",
    type=click.Choice(["ios", "android", "flutter", "react-native"]),
    required=True,
    help="Target platform.",
)
@click.option("--bundle-id", default=None, help="App bundle identifier (e.g. com.example.myapp).")
@click.option("--app-name", default=None, help="App display name.")
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="Use stricter thresholds (recommended for financial and health apps).",
)
def init(platform: str, bundle_id: str | None, app_name: str | None, strict: bool) -> None:
    """Create a mobileguard.json quality contract in the current directory.

    The contract is used by 'mobileguard contract' to evaluate AI-generated code
    against quality and security thresholds specific to your app and pipeline.

    \b
    Examples:
      mobileguard init --platform ios --bundle-id com.example.myapp
      mobileguard init --platform android --strict
    """
    out_path = Path("mobileguard.json")
    if out_path.exists():
        click.confirm(
            "mobileguard.json already exists. Overwrite?",
            abort=True,
        )

    thresholds = {
        "min_score": 0.85 if strict else 0.80,
        "max_critical_violations": 0,
        "max_error_violations": 0 if strict else 2,
        "min_regression_coverage": 0.90 if strict else 0.80,
        "min_crash_free_session_rate": 0.999 if strict else 0.997,
    }

    contract: dict[str, Any] = {
        "version": "1.0",
        "platform": platform,
        "app_name": app_name or "My App",
        "rules": {
            "enabled": ["app-store", "google-play", "eu-ai-act", "owasp"],
            "disabled": [],
        },
        "thresholds": thresholds,
        "stages": {
            "code-generation": {
                "min_score": thresholds["min_score"] - 0.10,
                "halt_on_critical": True,
            },
            "test-generation": {
                "min_score": thresholds["min_score"] - 0.05,
                "halt_on_critical": True,
            },
            "code-review": {
                "min_score": thresholds["min_score"],
                "halt_on_critical": True,
            },
        },
    }

    if bundle_id:
        contract["bundle_id"] = bundle_id

    out_path.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
    console.print("[green]Created:[/green] mobileguard.json")
    console.print(
        f"  Platform: {platform} · "
        f"Strict mode: {'on' if strict else 'off'} · "
        f"Min score: {thresholds['min_score']}"
    )
    console.print(
        "Run [cyan]mobileguard contract <path> --agent <agent-id>[/cyan]"
        " to evaluate AI-generated code."
    )


# ── mobileguard surface ───────────────────────────────────────────────────────

@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--platform",
    type=click.Choice(["ios", "android", "flutter", "react-native", "auto"]),
    default="auto",
    show_default=True,
    help="Target platform. 'auto' detects from file extensions.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "markdown"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option("--output", default=None, type=click.Path(), help="Write output to file.")
@click.option(
    "--risk",
    is_flag=True,
    default=False,
    help="Show risk assessment for each entry point.",
)
def surface(
    path: str,
    platform: str,
    output_format: str,
    output: str | None,
    risk: bool,
) -> None:
    """Map ambient AI agent entry points (Siri, AppIntents, AppFunctions).

    Scans for every entry point through which a platform AI agent (Siri,
    Apple Intelligence, Google Assistant) can take action in the app, then
    flags those accessing sensitive data without confirmation UI.

    \b
    Examples:
      mobileguard surface ./MyApp
      mobileguard surface ./MyApp --platform ios --format markdown
      mobileguard surface ./MyApp --risk
    """
    from mobileguard.surface import SurfaceScanner

    scanner = SurfaceScanner()
    result = scanner.scan(path, platform=platform, include_risk=risk)

    if output_format == "json":
        rendered = result.model_dump_json(indent=2)
    elif output_format == "markdown":
        rendered = _render_surface_markdown(result)
    else:
        _print_surface_table(result)
        rendered = None

    if rendered is not None:
        if output:
            Path(output).write_text(rendered, encoding="utf-8")
            console.print(f"[green]Written to:[/green] {output}")
        else:
            click.echo(rendered)


def _print_surface_table(result: Any) -> None:
    """Print ambient agent surface map as a rich table."""
    from mobileguard.surface import SurfaceScanResult

    assert isinstance(result, SurfaceScanResult)
    platform_label = result.platform.value.upper()

    console.print()
    console.print(
        Panel(
            f"[bold]MobileGuard Surface Map[/bold]\n"
            f"Project: [cyan]{Path(result.project_path).name}[/cyan] "
            f"({platform_label}) · "
            f"{len(result.entry_points)} ambient entry point"
            f"{'s' if len(result.entry_points) != 1 else ''} found",
            box=box.DOUBLE_EDGE,
            expand=False,
        )
    )

    if not result.entry_points:
        console.print("\n[green]No ambient agent entry points found.[/green]")
        return

    _RISK_STYLE = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
    }

    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        entries = [e for e in result.entry_points if e.risk_level == level]
        if not entries:
            continue
        style = _RISK_STYLE[level]
        console.print(f"\n[{style}]{level} ({len(entries)})[/{style}]")
        for e in entries:
            loc = f"{e.file_path}:{e.line_number}" if e.line_number else e.file_path
            access = ", ".join(e.data_access) if e.data_access else "None"
            confirm = "[green]Yes[/green]" if e.has_confirmation else "[yellow]Not found[/yellow]"
            console.print(f"  [{style}]{e.finding_id or e.entry_type}[/{style}]  "
                          f"[bold]{e.name}[/bold]  [dim]{loc}[/dim]")
            console.print(f"          Data access: {access} · Confirmation: {confirm}")
            if e.fix:
                console.print(f"          [green]Fix:[/green] {e.fix[:120]}")

    s = result.summary
    console.print()
    console.print("─" * 60)
    console.print(
        f"Surface summary: "
        f"[bold red]{s.get('critical', 0)} CRITICAL[/bold red] · "
        f"[red]{s.get('high', 0)} HIGH[/red] · "
        f"[yellow]{s.get('medium', 0)} MEDIUM[/yellow] · "
        f"[green]{s.get('low', 0)} LOW[/green]"
    )
    console.print("Run [cyan]mobileguard audit[/cyan] to include this surface map in the report.")
    console.print()


def _render_surface_markdown(result: Any) -> str:
    """Render surface scan result as Markdown governance documentation."""
    from mobileguard.surface import SurfaceScanResult

    assert isinstance(result, SurfaceScanResult)
    app_name = Path(result.project_path).name
    date_str = result.scanned_at.strftime("%Y-%m-%d")
    from mobileguard import __version__

    lines = [
        "# MobileGuard Ambient Agent Surface Map",
        f"**App:** {app_name} · **Platform:** {result.platform.value.upper()} "
        f"· **Date:** {date_str}",
        f"**Generated by:** MobileGuard v{__version__}",
        "",
        "## Summary",
        "This document maps all entry points through which platform-level AI agents "
        "(Siri, Apple Intelligence, Google Assistant, Gemini) can take action within "
        f"{app_name} without the user directly navigating the app interface.",
        "",
        "## Entry Points",
        "",
    ]

    for e in result.entry_points:
        risk_icon = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM"}.get(
            e.risk_level, ""
        )
        header = f"### {e.name}"
        if risk_icon:
            header += f" [{risk_icon}]"
        lines.append(header)
        lines.append(f"- **Type:** {e.entry_type}")
        loc_suffix = f":{e.line_number}" if e.line_number else ""
        lines.append(f"- **Location:** `{e.file_path}`{loc_suffix}")
        access_str = ", ".join(e.data_access) if e.data_access else "None"
        lines.append(f"- **Data accessed:** {access_str}")
        lines.append(f"- **Confirmation UI:** {'Present' if e.has_confirmation else 'NOT FOUND'}")
        lines.append(f"- **Risk:** {e.risk_level}")
        if e.finding_id:
            lines.append(f"- **Violation:** {e.finding_id}")
        if e.fix:
            lines.append(f"- **Required fix:** {e.fix}")
        lines.append("")

    lines += [
        "## Attestation",
        f"This surface map was generated automatically by MobileGuard on {date_str}. "
        "It represents the governance posture of the app's ambient AI surface at the "
        "time of scan. Intended for use in compliance documentation, App Store review "
        "responses, and EU AI Act Article 14 (human oversight) compliance evidence.",
        "",
    ]
    return "\n".join(lines)


# ── mobileguard releases ──────────────────────────────────────────────────────

@cli.command()
@click.option(
    "--platform",
    type=click.Choice(["ios", "android"]),
    default="ios",
    show_default=True,
    help="Store to scan. iOS uses iTunes Search API; Android uses google-play-scraper.",
)
@click.option(
    "--cohort",
    type=click.Choice(["ai-native", "traditional", "social"]),
    default="ai-native",
    show_default=True,
    help=(
        "Built-in search term preset. "
        "ai-native: 15 AI-related terms (Study 3 Cohort 1). "
        "traditional: 15 category terms (Study 3 Cohort 2). "
        "social: social media and messaging apps (TAC-M focus)."
    ),
)
@click.option(
    "--terms",
    default=None,
    help="Comma-separated custom search terms (overrides --cohort).",
)
@click.option(
    "--limit",
    default=50,
    show_default=True,
    type=int,
    help="Max apps to fetch per search term (max 200 for iOS, 30 for Android).",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output",
    type=click.Path(),
    default=None,
    help="Write results to file instead of stdout.",
)
@click.option(
    "--fail-on",
    "fail_on",
    type=click.Choice(["critical", "warning", "info"]),
    default=None,
    help="Exit 1 if any finding at this severity or above is found.",
)
def releases(
    platform: str,
    cohort: str,
    terms: str | None,
    limit: int,
    output_format: str,
    output: str | None,
    fail_on: str | None,
) -> None:
    """Scan App Store / Google Play release notes for AI governance signals (AS-009).

    Implements the AS-009 Release Notes AI Disclosure Scanner from the MobileGuard
    research paper (DOI: 10.5281/zenodo.20970167), validated against 942 real mobile
    platform apps with a 4.0% governance signal rate.

    \\b
    Rules applied:
      AS-009-A  CRITICAL  Multiple named AI providers without consent modal update
      AS-009-B  WARNING   AI introduced to non-AI user base without disclosure
      AS-009-C  INFO      Training data collection without opt-out disclosure
      AS-009-D  WARNING   Biometric/behavioral data without explicit consent
      AS-009-F  CRITICAL  Autonomous action without per-action confirmation (TAC-M)

    \\b
    Examples:
      mobileguard releases --platform ios --cohort ai-native
      mobileguard releases --platform ios --cohort social --limit 30
      mobileguard releases --platform ios --terms "fitness tracker,workout app"
      mobileguard releases --platform ios --cohort traditional --format csv --output results.csv
      mobileguard releases --platform android --cohort ai-native
    """
    from mobileguard.releases import run_releases_scan, COHORT_TERMS

    custom_terms = [t.strip() for t in terms.split(",")] if terms else None
    terms_preview = custom_terms or COHORT_TERMS.get(cohort, [])

    err_console.print(
        f"[dim]Scanning {platform.upper()} release notes "
        f"({'custom terms' if custom_terms else cohort} cohort, "
        f"{len(terms_preview)} terms, max {limit}/term)...[/dim]"
    )

    scanned_so_far = [0]
    flagged_so_far = [0]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        task = progress.add_task("Fetching apps...", total=None)

        def _cb(term: str, fetched: int, flagged: int) -> None:
            scanned_so_far[0] += fetched
            flagged_so_far[0] += flagged
            progress.update(
                task,
                description=(
                    f"'{term}' — {scanned_so_far[0]} apps scanned, "
                    f"{flagged_so_far[0]} flagged"
                ),
            )

        result = run_releases_scan(
            platform=platform,
            cohort=cohort,
            terms=custom_terms,
            limit_per_term=limit,
            progress_callback=_cb,
        )

    # Render warnings
    for warn in result.scan_warnings:
        err_console.print(f"[yellow]Warning:[/yellow] {warn}")

    # Render output
    if output_format == "json":
        import dataclasses
        rendered = json.dumps(
            [dataclasses.asdict(f) for f in result.findings], indent=2
        )
    elif output_format == "csv":
        rendered = _render_releases_csv(result)
    else:
        rendered = None

    if rendered is not None:
        if output:
            Path(output).write_text(rendered, encoding="utf-8")
            console.print(f"[green]Results written to:[/green] {output}")
        else:
            click.echo(rendered)
    else:
        _print_releases_table(result)

    # Exit code
    if fail_on:
        sev_weight = {"critical": 3, "warning": 2, "info": 1}
        threshold = sev_weight[fail_on]
        if any(sev_weight.get(f.severity, 0) >= threshold for f in result.findings):
            sys.exit(1)


def _print_releases_table(result: Any) -> None:
    """Print AS-009 scan results as a rich table."""
    from mobileguard.releases import ReleasesScanResult
    assert isinstance(result, ReleasesScanResult)

    flag_pct = f"{result.flag_rate * 100:.1f}%"
    console.print()
    console.print(
        Panel(
            f"[bold]MobileGuard Releases Scan — AS-009[/bold]\n"
            f"Platform: [cyan]{result.platform.upper()}[/cyan] · "
            f"Cohort: {result.cohort} · "
            f"{result.apps_scanned} apps scanned · "
            f"{result.apps_flagged} flagged ({flag_pct}) · "
            f"{result.scan_duration_seconds}s",
            box=box.DOUBLE_EDGE,
            expand=False,
        )
    )

    if result.first_party_excluded:
        console.print(
            f"[dim]First-party apps excluded: {result.first_party_excluded} "
            f"(Anthropic, OpenAI, Meta, Google, Microsoft, Apple)[/dim]"
        )

    if result.android_null_count:
        console.print(
            f"[yellow]Android null recentChanges: {result.android_null_count} "
            f"(Google Play does not mandate release note disclosure)[/yellow]"
        )

    if not result.findings:
        console.print("\n[green]No AS-009 governance signals found.[/green]")
        return

    _SEV_STYLE = {"critical": "bold red", "warning": "yellow", "info": "blue"}

    for sev in ("critical", "warning", "info"):
        findings_at_sev = [f for f in result.findings if f.severity == sev]
        if not findings_at_sev:
            continue
        style = _SEV_STYLE[sev]
        console.print(f"\n[{style}]{sev.upper()} ({len(findings_at_sev)})[/{style}]")
        for f in findings_at_sev:
            console.print(
                f"  [{style}]{f.rule_id}[/{style}]  "
                f"[bold]{f.app_name}[/bold]  "
                f"[dim]{f.developer} · v{f.version} · {f.category}[/dim]"
            )
            console.print(f"          {f.description}")
            if f.matched_text:
                console.print(f"          [dim]→ \"{f.matched_text[:100]}\"[/dim]")
            console.print(f"          [green]→ Fix:[/green] {f.fix[:120]}")

    s = result.summary
    console.print()
    console.print("─" * 60)
    console.print(
        f"Summary: [bold red]{s.get('critical', 0)} CRITICAL[/bold red] · "
        f"[yellow]{s.get('warning', 0)} WARNING[/yellow] · "
        f"[blue]{s.get('info', 0)} INFO[/blue] · "
        f"Flag rate: {flag_pct}"
    )
    console.print()


def _render_releases_csv(result: Any) -> str:
    """Render releases findings as CSV."""
    import csv
    import io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "severity", "rule_id", "pillar", "app_name", "developer",
        "bundle_id", "version", "category", "platform",
        "description", "matched_text", "fix", "search_term", "scanned_at",
    ])
    for f in result.findings:
        writer.writerow([
            f.severity, f.rule_id, f.pillar, f.app_name, f.developer,
            f.bundle_id, f.version, f.category, f.platform,
            f.description, f.matched_text, f.fix, f.search_term, f.scanned_at,
        ])
    return buf.getvalue()


# ── mobileguard preflight ─────────────────────────────────────────────────────

@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--platform",
    type=click.Choice(["ios", "android", "auto"]),
    default="auto",
    show_default=True,
    help="Platform to scan. 'auto' detects from file extensions.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "sarif"]),
    default="table",
    show_default=True,
)
@click.option(
    "--output",
    type=click.Path(),
    default=None,
    help="Write results to file.",
)
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="Exit 1 on any WARNING or above (default: exit 1 on CRITICAL only).",
)
def preflight(path: str, platform: str, output_format: str, output: str | None, strict: bool) -> None:
    """Run ALL MobileGuard checks in one command — the pre-submission gate.

    Runs scan (source code) + privacy manifest checks in sequence and produces
    a unified CLEARED / BLOCKED report. Designed to run in CI/CD on every PR
    and before every App Store or Google Play submission.

    \b
    Checks run:
      PGSG  Source code scan (AS-001 through AS-012, EU-001, OW-001..005)
      PGSG  Privacy manifest validation (PrivacyInfo.xcprivacy / AndroidManifest)
      PGSG  Platform reference detection (AS-010) — catches Android→iOS port artifacts
      PGSG  Placeholder content detection (AS-011) — Guideline 2.1 App Completeness
      PGSG  Vague permission strings (AS-012) — Guideline 5.1.1

    \b
    Evidence basis:
      Apple 2024 Transparency Report: 1.93M rejections (25% of submissions)
      40%+ of unresolved rejections: App Completeness (placeholder content)
      Statista 2024: ~1/3 of rejections cite privacy explanation gaps
      MobileGuard paper: DOI 10.5281/zenodo.20970167

    \b
    Examples:
      mobileguard preflight .
      mobileguard preflight ./MyApp --platform ios --strict
      mobileguard preflight ./MyApp --format sarif --output results.sarif
    """
    from mobileguard.scanner import run_scan

    err_console.print(f"[dim]MobileGuard preflight — {path}[/dim]")
    err_console.print(f"[dim]Platform: {platform} | Checks: scan + privacy + completeness[/dim]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning source files...", total=None)
        result = run_scan(path, platform=platform if platform != "auto" else None)
        progress.update(task, description=f"Scanned {result.files_scanned} files")

    # Render output
    if output_format in ("json", "sarif"):
        rendered = _render_scan(result, output_format, path)
        if output:
            Path(output).write_text(rendered, encoding="utf-8")
            console.print(f"[green]Results written to:[/green] {output}")
        else:
            click.echo(rendered)
        if strict:
            if not result.passed or any(
                f.severity.value in ("warning", "info") for f in result.findings
            ):
                sys.exit(1)
        elif not result.passed:
            sys.exit(1)
        return

    # Table output — GREENLIT / BLOCKED banner
    _print_table_result(result, path)

    console.print()
    if result.passed and result.summary.get("warning", 0) == 0:
        console.print(
            Panel(
                "[bold green]✅  CLEARED[/bold green]\n"
                "Zero critical or warning findings. "
                "This build is ready for App Store or Google Play submission.\n\n"
                "[dim]Evidence: MobileGuard v3.0.0 preflight — DOI: 10.5281/zenodo.20970167[/dim]",
                box=box.DOUBLE_EDGE,
                expand=False,
            )
        )
    elif result.passed:
        console.print(
            Panel(
                "[bold yellow]⚠️  CLEARED WITH WARNINGS[/bold yellow]\n"
                f"{result.summary.get('warning', 0)} warning(s) found. "
                "No critical violations. Review warnings before submission.\n\n"
                "[dim]Use --strict to treat warnings as blocking.[/dim]",
                box=box.DOUBLE_EDGE,
                expand=False,
            )
        )
    else:
        critical = result.summary.get("critical", 0)
        console.print(
            Panel(
                f"[bold red]🔴  BLOCKED — {critical} CRITICAL finding(s)[/bold red]\n"
                "Fix all CRITICAL findings before submitting to App Store or Google Play.\n"
                "Submitting with these findings risks rejection or post-launch removal.\n\n"
                "[dim]Run: mobileguard scan . --format json for full details[/dim]",
                box=box.DOUBLE_EDGE,
                expand=False,
            )
        )
        sys.exit(1)

    if strict and result.summary.get("warning", 0) > 0:
        sys.exit(1)
