# SECURITY-REVIEWED: 2026-07-14 | RULES: v2.6.0-draft
"""CLI for secptest-benchmark — up, down, verify, self-test, report commands.

v4.0 adds:
  - report command now outputs Markdown (report.md) for LLM consumption
  - report.json still written as programmatic interface
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import argparse

PROJECT_ROOT = Path(__file__).parent.parent.parent
COMPOSE_FILE = PROJECT_ROOT / "targets" / "docker-compose.yml"
ASSERTIONS_FILE = PROJECT_ROOT / "assertions.json"


def cmd_up(args: argparse.Namespace) -> None:
    """Bring up the target range via docker compose and wait for health."""
    if not COMPOSE_FILE.exists():
        print(f"Error: compose file not found at {COMPOSE_FILE}", file=sys.stderr)
        print("Run 'benchmark init' first to create target infrastructure.", file=sys.stderr)
        sys.exit(1)

    import subprocess
    print(f"Starting target range from {COMPOSE_FILE} ...")
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"docker compose up failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    print("Target containers started.")

    # Health check: wait for services to be reachable
    print("Waiting for services to become healthy ...")
    for attempt in range(1, 13):
        health_result = subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), "ps", "--format", "json"],
            capture_output=True, text=True,
        )
        if health_result.returncode == 0 and health_result.stdout.strip():
            lines = health_result.stdout.strip().splitlines()
            healthy = 0
            total = len(lines)
            for line in lines:
                try:
                    svc = json.loads(line)
                    if svc.get("Health") == "healthy" or svc.get("Status") == "running":
                        healthy += 1
                except json.JSONDecodeError:
                    healthy += 1  # assume running if parse fails
            if healthy >= total and total > 0:
                print(f"All {total} services healthy after {attempt * 5}s.")
                break
        time.sleep(5)
    else:
        print("Warning: some services may not be fully healthy yet.", file=sys.stderr)

    # Print integration info
    if ASSERTIONS_FILE.exists():
        print(f"\nAssertions file: {ASSERTIONS_FILE}")
    print("\nTarget range is up. Run 'benchmark verify <sarif-file>' to evaluate results.")


def cmd_down(args: argparse.Namespace) -> None:
    """Shut down the target range via docker compose."""
    if not COMPOSE_FILE.exists():
        print(f"Error: compose file not found at {COMPOSE_FILE}", file=sys.stderr)
        sys.exit(1)

    import subprocess
    print(f"Stopping target range from {COMPOSE_FILE} ...")
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "down"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"docker compose down failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    print("Target range stopped.")


def cmd_verify(args: argparse.Namespace) -> None:
    """Parse SARIF file, load assertions, run verifier, and write report."""
    from secptest_benchmark.sarif_schema import parse_sarif
    from secptest_benchmark.assertions import load_assertions
    from secptest_benchmark.verifier import Verifier

    sarif_path = Path(args.sarif_file)
    if not sarif_path.exists():
        print(f"Error: SARIF file not found at {sarif_path}", file=sys.stderr)
        sys.exit(1)

    assertions_path = Path(args.assertions) if args.assertions else ASSERTIONS_FILE
    if not assertions_path.exists():
        print(f"Error: assertions file not found at {assertions_path}", file=sys.stderr)
        sys.exit(1)

    # Parse SARIF
    sarif_data = json.loads(sarif_path.read_text(encoding="utf-8"))
    findings = parse_sarif(sarif_data)
    print(f"Loaded {len(findings.results)} findings from {sarif_path}")

    # Load assertions
    suite = load_assertions(assertions_path)
    print(f"Loaded {len(suite.scenarios)} scenarios from {assertions_path}")

    # Verify
    report = Verifier().verify(findings.results, suite)

    # Write report
    output_path = Path(args.output) if args.output else PROJECT_ROOT / "report.json"
    report_data = report.to_dict()
    output_path.write_text(json.dumps(report_data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Report written to {output_path}")

    # Print summary
    overall = report.overall
    print(f"\nOverall: {overall['total_discovered']}/{overall['total_assertions']} assertions discovered "
          f"(rate: {overall['overall_discovery_rate']:.1%})")
    print(f"Extra discoveries: {overall['extra_discoveries']}")
    for sc in report.scenarios:
        print(f"  {sc.scenario_id} ({sc.scenario_name}): "
              f"{len(sc.discovered)} discovered, {len(sc.missing)} missing, "
              f"rate={sc.discovery_rate:.1%}, minimum={sc.minimum_discovered}, "
              f"meets={sc.meets_minimum}")


def cmd_self_test(args: argparse.Namespace) -> None:
    """Run vulnerability self-test against the target range."""
    from secptest_benchmark.vuln_verifier import VulnVerifier

    base_url = args.base_url or "http://localhost:80"
    priv_url = args.priv_url or "http://localhost:8081"
    print(f"Running vulnerability self-test against {base_url} (pub) + {priv_url} (priv) ...")
    print()

    verifier = VulnVerifier(base_url=base_url, priv_url=priv_url)
    report = verifier.run_all()

    # Print per-scenario summary
    for sid, stats in report.scenarios.items():
        sname = stats["scenario_name"]
        verified = stats["verified"]
        total = stats["total"]
        rate = stats["rate"]
        bar = "PASS" if stats["failed"] == 0 else "FAIL"
        print(f"  [{bar}] {sid} {sname}: {verified}/{total} verified ({rate:.0%})")

    print()
    print(f"Total: {report.verified}/{report.total} verified, {report.failed} failed")

    # Print failures
    failures = [r for r in report.results if not r.verified]
    if failures:
        print()
        print("=" * 65)
        print(f"FAILURES ({len(failures)}):")
        for f in failures:
            err_detail = f.error or ""
            if f.missing_flags:
                err_detail = f"missing flags: {f.missing_flags}"
            print(f"  [{f.severity}] {f.test_id} {f.name}")
            print(f"         status={f.status_code}, {err_detail}")
            if f.response_snippet:
                snippet = f.response_snippet[:200].replace("\n", "\\n")
                print(f"         response: {snippet}")

    # Write report if requested
    if args.output:
        output_path = Path(args.output)
        output_path.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"\nReport written to {output_path}")

    if report.failed > 0:
        sys.exit(1)


def cmd_report(args: argparse.Namespace) -> None:
    """Read a report.json file and print formatted terminal + Markdown output."""
    from secptest_benchmark.report_md import render_report_md

    report_path = Path(args.report_file) if args.report_file else PROJECT_ROOT / "report.json"
    if not report_path.exists():
        print(f"Error: report file not found at {report_path}", file=sys.stderr)
        sys.exit(1)

    report_data = json.loads(report_path.read_text(encoding="utf-8"))

    # ── Terminal summary (existing behavior) ──
    print(f"=== Benchmark Report for {report_data.get('domain', 'N/A')} ===")
    print(f"Version: {report_data.get('version', 'N/A')}")
    print()

    overall = report_data.get("overall", {})
    total_discovered = overall.get("total_discovered", 0)
    total_assertions = overall.get("total_assertions", 0)
    total_fp = overall.get("total_false_positives", 0)
    total_safe = overall.get("total_safe_endpoints", 0)
    total_tn = overall.get("total_true_negatives", 0)
    rate = overall.get("overall_discovery_rate", 0.0)
    extras = overall.get("extra_discoveries", 0)
    ref = overall.get("reference_metrics", {})

    print(f"Vuln endpoints: {total_discovered}/{total_assertions} discovered ({rate:.1%})")
    print(f"Safe endpoints: {total_tn}/{total_safe} correct, {total_fp} false positives")
    print(f"Extra discoveries: {extras}")
    if ref:
        print(f"Reference: precision={ref.get('total_precision', 0):.1%} "
              f"recall={ref.get('total_recall', 0):.1%} "
              f"fp_rate={ref.get('total_fp_rate', 0):.1%}")
    print()

    for sc in report_data.get("scenarios", []):
        sid = sc.get("scenario_id", "?")
        sname = sc.get("scenario_name", "?")
        stype = sc.get("scenario_type", "vuln")
        discovered_list = sc.get("discovered", [])
        missing_list = sc.get("missing", [])
        disc_rate = sc.get("discovery_rate", 0.0)
        meets = sc.get("meets_minimum", False)
        minimum = sc.get("minimum_discovered", 0)
        type_mark = "[靶场]" if stype == "vuln" else "[普通]"
        status_mark = "PASS" if meets else "FAIL"

        print(f"  {type_mark} [{status_mark}] {sid} {sname}: "
              f"{len(discovered_list)}/{len(discovered_list)+len(missing_list)} "
              f"discovered (rate={disc_rate:.1%}, min={minimum})")

        # Show FP summary
        fp_count = len(sc.get("false_positives", []))
        tn_count = len(sc.get("true_negatives", []))
        total_safe = sc.get("total_safe_endpoints", 0)
        if total_safe > 0:
            print(f"         safe endpoints: {tn_count}/{total_safe} TN, {fp_count} FP")

        for d in discovered_list:
            confidence_mark = {"confirmed": "[C]", "unconfirmed": "[U]", "weak": "[W]"}.get(
                d.get("confidence", ""), "[?]"
            )
            print(f"      {confidence_mark} {d.get('assertion_id', '?')} via {d.get('match_method', '?')} "
                  f"→ {d.get('finding_uri', 'N/A')}")

        for m in missing_list:
            print(f"      [MISS] {m.get('assertion_id', '?')} (severity: {m.get('severity', 'N/A')})")

    print()
    extra_list = report_data.get("extra_discoveries", [])
    if extra_list:
        print("Extra discoveries (not in assertions or safe endpoints):")
        for e in extra_list:
            print(f"  - {e.get('rule_id', 'N/A')}: {e.get('uri', 'N/A')} "
                  f"(category: {e.get('category', 'N/A')})")
    else:
        print("No extra discoveries.")

    # ── Markdown output (new v4.0) ──
    md_content = render_report_md(report_data)
    md_path = report_path.with_suffix(".md")
    md_path.write_text(md_content, encoding="utf-8")
    print(f"\nMarkdown report written to {md_path}")


def main() -> None:
    """Entry point for the benchmark CLI."""
    parser = argparse.ArgumentParser(
        prog="benchmark",
        description="SecpTest Benchmark — independent target range + evaluation protocol",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # up
    up_parser = subparsers.add_parser("up", help="Start the target range (docker compose up)")
    up_parser.set_defaults(func=cmd_up)

    # down
    down_parser = subparsers.add_parser("down", help="Stop the target range (docker compose down)")
    down_parser.set_defaults(func=cmd_down)

    # verify
    verify_parser = subparsers.add_parser("verify", help="Parse SARIF + run verifier → report.json")
    verify_parser.add_argument("sarif_file", help="Path to SARIF JSON file to evaluate")
    verify_parser.add_argument("--assertions", default=str(ASSERTIONS_FILE),
                               help=f"Path to assertions.json (default: {ASSERTIONS_FILE})")
    verify_parser.add_argument("--output", default=str(PROJECT_ROOT / "report.json"),
                               help=f"Path to write report JSON (default: {PROJECT_ROOT / 'report.json'})")
    verify_parser.set_defaults(func=cmd_verify)

    # self-test
    st_parser = subparsers.add_parser("self-test", help="Verify target range vulnerabilities are real")
    st_parser.add_argument("--base-url", default="http://localhost:80",
                           help="Base URL of pub-gateway (default: http://localhost:80)")
    st_parser.add_argument("--priv-url", default="http://localhost:8081",
                           help="Base URL of priv-gateway for Host collision tests (default: http://localhost:8081)")
    st_parser.add_argument("--output", default=None,
                           help="Path to write JSON report (default: stdout only)")
    st_parser.set_defaults(func=cmd_self_test)

    # report
    report_parser = subparsers.add_parser("report", help="Print formatted report from report.json")
    report_parser.add_argument("report_file", nargs="?", default=str(PROJECT_ROOT / "report.json"),
                               help=f"Path to report JSON (default: {PROJECT_ROOT / 'report.json'})")
    report_parser.set_defaults(func=cmd_report)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    args.func(args)


if __name__ == "__main__":
    main()
