"""Command-line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from . import __version__
from .checks import load_checks
from .context import Options
from .diff import DiffError, diff_documents, load_findings, render_diff_html, worst_new_severity
from .model import SEVERITY_RANK, Severity
from .pipeline import analyze, build_document
from .redact import Redactor
from .report import write_outputs

SEV_COLORS = {"Critical": "red", "High": "bright_red", "Medium": "yellow", "Low": "blue", "Info": "white"}
SEVERITY_CHOICE = click.Choice([s.value.lower() for s in Severity], case_sensitive=False)


def _sev(text: str) -> str:
    return click.style(f"{text:<8}", fg=SEV_COLORS.get(text, "white"), bold=text == "Critical")


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="houndreport")
def main() -> None:
    """Offline analysis reports for BloodHound CE / SharpHound CE collector output."""


@main.command("analyze")
@click.argument("input_path", type=click.Path(exists=True, path_type=Path))
@click.option("-o", "--output", "output_dir", type=click.Path(file_okay=False, path_type=Path),
              default=Path("houndreport-out"), show_default=True, help="Directory for report.html, findings.json and csv/.")
@click.option("--stale-days", type=click.IntRange(min=1), default=90, show_default=True,
              help="Days without logon before an enabled account counts as stale.")
@click.option("--top-paths", type=click.IntRange(min=0), default=10, show_default=True,
              help="Number of attack paths drawn in the HTML report.")
@click.option("--redact", is_flag=True, help="Replace user, host and domain names with stable hashed tokens.")
@click.option("--redact-salt", envvar="HOUNDREPORT_REDACT_SALT", default="", show_envvar=True,
              help="Secret salt for --redact. Reuse it to keep redacted reports diffable.")
@click.option("--client-name", default="", help="Client / organisation name shown in the report header.")
@click.option("--as-of", type=click.DateTime(formats=["%Y-%m-%d"]), default=None,
              help="Reference date for staleness (default: newest logon timestamp in the data).")
@click.option("--skip-check", "skip_checks", multiple=True, metavar="NAME_OR_ID",
              help="Skip a check module (e.g. adcs) or a finding ID (e.g. HR-HYG-005). Repeatable.")
@click.option("-q", "--quiet", is_flag=True, help="Only print errors.")
def analyze_cmd(input_path: Path, output_dir: Path, stale_days: int, top_paths: int, redact: bool,
                redact_salt: str, client_name: str, as_of, skip_checks: tuple[str, ...], quiet: bool) -> None:
    """Analyse a SharpHound .zip, a folder of JSON files, or a single JSON file."""
    options = Options(stale_days=stale_days, top_paths=top_paths, as_of=as_of, skip_checks=skip_checks)
    try:
        result = analyze(input_path, options)
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc
    if not result.graph.files:
        for w in result.warnings:
            click.echo(f"warning: {w}", err=True)
        raise click.ClickException("no usable SharpHound data found in the input")
    if redact and not redact_salt and not quiet:
        click.echo("note: --redact without --redact-salt; short names can be brute-forced from the hashes.", err=True)
    redactor = Redactor(result.graph, redact_salt) if redact else None
    doc = build_document(result, client_name=client_name, redactor=redactor)
    paths = write_outputs(doc, output_dir)

    for w in doc["inputs"]["warnings"]:
        click.echo(click.style("warning: ", fg="yellow") + w, err=True)
    if quiet:
        return
    risk = doc["risk"]
    click.echo(f"Risk: {risk['rating']} ({risk['score']}/100)   "
               f"Tier 0: {doc['summary']['tier0_principals']}   "
               f"Users with path to Tier 0: {doc['summary']['users_with_path']}/{doc['summary']['enabled_users']}")
    for f in doc["findings"]:
        click.echo(f"  {_sev(f['severity'])} {f['id']:<14} {f['title']} ({f['affected_count']})")
    click.echo(f"\nWrote {paths['html']}\n      {paths['json']}\n      {paths['csv_dir']}")


@main.command("diff")
@click.argument("old", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("new", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--html", "html_out", type=click.Path(dir_okay=False, path_type=Path), help="Also write an HTML comparison.")
@click.option("--json", "json_out", type=click.Path(dir_okay=False, path_type=Path), help="Also write the comparison as JSON.")
@click.option("--fail-on-new", type=SEVERITY_CHOICE, default=None,
              help="Exit with status 2 if anything new at or above this severity appeared.")
@click.option("-v", "--verbose", is_flag=True, help="List new and resolved objects of persisting findings.")
def diff_cmd(old: Path, new: Path, html_out: Path | None, json_out: Path | None,
             fail_on_new: str | None, verbose: bool) -> None:
    """Compare two findings.json files: new, resolved and persisting findings."""
    try:
        result = diff_documents(load_findings(old), load_findings(new))
    except DiffError as exc:
        raise click.ClickException(str(exc)) from exc

    for w in result["warnings"]:
        click.echo(click.style("warning: ", fg="yellow") + w, err=True)
    o, n = result["old"]["risk"], result["new"]["risk"]
    delta = result["risk_delta"]
    click.echo(f"Risk score: {o.get('score', '?')} ({o.get('rating', '?')}) -> {n.get('score', '?')} "
               f"({n.get('rating', '?')})" + (f"  [{delta:+d}]" if delta is not None else ""))

    def section(title: str, items: list, color: str) -> None:
        click.echo(click.style(f"\n{title} ({len(items)})", fg=color, bold=True))
        for f in items:
            click.echo(f"  {_sev(f['severity'])} {f['id']:<14} {f['title']} ({f['affected_count']})")

    section("NEW", result["new_findings"], "red")
    section("RESOLVED", result["resolved_findings"], "green")
    click.echo(click.style(f"\nPERSISTING ({len(result['persisting_findings'])})", bold=True))
    for p in result["persisting_findings"]:
        change = f"+{len(p['new_objects'])} / -{len(p['resolved_objects'])}"
        sev_note = f" (was {p['old_severity']})" if p["severity_changed"] else ""
        click.echo(f"  {_sev(p['severity'])} {p['id']:<14} {p['title']} [{change}]{sev_note}")
        if verbose:
            for a in p["new_objects"]:
                click.echo(click.style(f"      + {a['name']}", fg="red"))
            for a in p["resolved_objects"]:
                click.echo(click.style(f"      - {a['name']}", fg="green"))

    if html_out:
        html_out.parent.mkdir(parents=True, exist_ok=True)
        html_out.write_text(render_diff_html(result), encoding="utf-8")
        click.echo(f"\nWrote {html_out}")
    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        click.echo(f"Wrote {json_out}")
    if fail_on_new and worst_new_severity(result) >= SEVERITY_RANK[Severity.parse(fail_on_new).value]:
        sys.exit(2)


@main.command("list-checks")
def list_checks_cmd() -> None:
    """List registered check modules and the finding IDs they produce."""
    for name, registered in sorted(load_checks().items()):
        click.echo(f"{name:<12} {', '.join(registered.ids) or '(plugin)'}")
