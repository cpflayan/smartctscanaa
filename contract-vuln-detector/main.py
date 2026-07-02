#!/usr/bin/env python3
"""
Contract Vulnerability Detector - Main CLI Entry Point

Usage:
    # Scan a local Solidity file
    python main.py scan --file contracts/MyToken.sol

    # Scan an on-chain contract
    python main.py scan --address 0x1234... --chain ethereum

    # Scan with specific scanner only
    python main.py scan --file contracts/MyToken.sol --scanner pattern

    # Skip AI analysis (script-only mode)
    python main.py scan --file contracts/MyToken.sol --no-ai

    # Generate report from previous scan
    python main.py report --output ./reports/
"""

import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import click
import yaml

# Ensure project root is on path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from scanners.base_scanner import BaseScanner, Finding, Severity, ScannerType
from scanners.pattern_scanner import PatternScanner
from scanners.slither_scanner import SlitherScanner
from scanners.mythril_scanner import MythrilScanner
from fetchers.multi_chain import MultiChainFetcher
from analyzer.ai_analyzer import AIAnalyzer
from analyzer.severity import SeverityScorer
from reports.report_generator import ReportGenerator

# ─── Logging Setup ────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("main")


# ─── Config Loader ────────────────────────────────────────────────────────────────

def load_config(config_path: str = None) -> dict:
    """Load configuration from YAML file."""
    if config_path is None:
        config_path = str(PROJECT_ROOT / "config" / "settings.yaml")

    if not os.path.exists(config_path):
        logger.warning(f"Config file not found: {config_path}, using defaults")
        return {}

    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# ─── Source Loader ─────────────────────────────────────────────────────────────────

def load_source(
    file_path: str = None,
    address: str = None,
    chain: str = "ethereum",
    config: dict = None,
) -> tuple[str, dict]:
    """
    Load contract source code from file or chain.

    Returns:
        (source_code, metadata_dict)
    """
    metadata = {}

    if file_path:
        # Load from local file
        abs_path = os.path.abspath(file_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"File not found: {abs_path}")

        with open(abs_path, "r", encoding="utf-8") as f:
            source_code = f.read()

        metadata = {
            "source": "local_file",
            "file_path": abs_path,
            "contract_name": Path(abs_path).stem,
        }
        logger.info(f"Loaded source from: {abs_path}")

    elif address:
        # Load from chain
        chain_config = config.get("chains", {}) if config else {}
        fetcher = MultiChainFetcher(chain_config)
        source_code, metadata = fetcher.fetch(address, chain=chain)

        if source_code is None:
            error = metadata.get("error", "unknown error")
            raise RuntimeError(f"Failed to fetch contract source: {error}")

        metadata["source"] = "on_chain"
        logger.info(f"Fetched source from {chain}: {address}")

    else:
        raise ValueError("Must specify either --file or --address")

    return source_code, metadata


# ─── Scanner Runner ────────────────────────────────────────────────────────────────

def run_scanners(
    source_code: str,
    file_path: str,
    config: dict,
    scanner_filter: str = None,
    parallel: bool = True,
) -> list[Finding]:
    """
    Run all enabled scanners and collect findings.

    Args:
        source_code: Solidity source code.
        file_path: File path for reference.
        config: Scanner configuration.
        scanner_filter: If set, only run this scanner (pattern/slither/mythril).
        parallel: Run scanners in parallel threads.

    Returns:
        Combined list of findings from all scanners.
    """
    scanner_configs = config.get("scanners", {})

    # Build scanner instances
    scanners: list[BaseScanner] = []

    if not scanner_filter or scanner_filter == "pattern":
        scanners.append(PatternScanner(scanner_configs.get("pattern", {})))

    if not scanner_filter or scanner_filter == "slither":
        scanners.append(SlitherScanner(scanner_configs.get("slither", {})))

    if not scanner_filter or scanner_filter == "mythril":
        scanners.append(MythrilScanner(scanner_configs.get("mythril", {})))

    # Filter disabled scanners
    scanners = [s for s in scanners if s.enabled]

    if not scanners:
        logger.warning("No scanners enabled!")
        return []

    logger.info(f"Running {len(scanners)} scanner(s): {[s.scanner_type.value for s in scanners]}")

    all_findings: list[Finding] = []

    if parallel and len(scanners) > 1:
        # Run scanners in parallel
        with ThreadPoolExecutor(max_workers=len(scanners)) as executor:
            futures = {
                executor.submit(s.scan, source_code, file_path): s
                for s in scanners
            }
            for future in as_completed(futures):
                scanner = futures[future]
                try:
                    findings = future.result()
                    logger.info(
                        f"  {scanner.scanner_type.value}: found {len(findings)} issue(s)"
                    )
                    all_findings.extend(findings)
                except Exception as e:
                    logger.error(f"  {scanner.scanner_type.value} failed: {e}")
    else:
        # Run sequentially
        for scanner in scanners:
            try:
                logger.info(f"  Running {scanner.scanner_type.value}...")
                findings = scanner.scan(source_code, file_path)
                logger.info(f"  {scanner.scanner_type.value}: found {len(findings)} issue(s)")
                all_findings.extend(findings)
            except Exception as e:
                logger.error(f"  {scanner.scanner_type.value} failed: {e}")

    logger.info(f"Total findings: {len(all_findings)}")
    return all_findings


# ─── CLI Commands ──────────────────────────────────────────────────────────────────

@click.group()
@click.option("--config", "-c", default=None, help="Path to config YAML file")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx, config, verbose):
    """Contract Vulnerability Detector - AI-powered smart contract security scanner."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    ctx.ensure_object(dict)
    ctx.obj["config"] = load_config(config)


@cli.command()
@click.option("--file", "-f", "file_path", default=None, help="Path to .sol file")
@click.option("--address", "-a", default=None, help="Contract address (0x...)")
@click.option("--chain", default="ethereum", help="Chain name (ethereum/bsc/polygon/arbitrum/optimism)")
@click.option("--scanner", "-s", default=None,
              type=click.Choice(["pattern", "slither", "mythril"]),
              help="Run only this scanner")
@click.option("--no-ai", is_flag=True, help="Skip AI analysis (script-only mode)")
@click.option("--output", "-o", default="./reports", help="Output directory for reports")
@click.pass_context
def scan(ctx, file_path, address, chain, scanner, no_ai, output):
    """Scan a smart contract for vulnerabilities."""

    config = ctx.obj["config"]

    if not file_path and not address:
        click.echo("Error: Must specify either --file or --address", err=True)
        sys.exit(1)

    start_time = time.time()

    # Step 1: Load source code
    click.echo("\n[1/4] Loading contract source...")
    try:
        source_code, contract_info = load_source(
            file_path=file_path, address=address, chain=chain, config=config
        )
    except Exception as e:
        click.echo(f"Error loading source: {e}", err=True)
        sys.exit(1)

    source_file = file_path or address or "<unknown>"

    # Step 2: Run scanners
    click.echo("[2/4] Running vulnerability scanners...")
    findings = run_scanners(
        source_code, source_file, config,
        scanner_filter=scanner, parallel=True
    )

    if not findings:
        click.echo("\nNo vulnerabilities found. Contract appears clean!")
        return

    # Step 3: AI Analysis (optional)
    batch_summary = {}
    if not no_ai:
        click.echo(f"[3/4] Running AI deep analysis on {len(findings)} finding(s)...")
        llm_config = config.get("llm", {})
        analyzer = AIAnalyzer(llm_config)

        def on_progress(idx, total):
            click.echo(f"  Analyzing finding {idx + 1}/{total}...", nl=False)
            click.echo("\r", nl=False)

        findings, batch_summary = analyzer.analyze_all(
            findings, source_code,
            contract_name=contract_info.get("contract_name", "Unknown"),
            solc_version=contract_info.get("compiler_version", "unknown"),
            file_path=source_file,
            on_progress=on_progress,
        )
        click.echo("")
    else:
        click.echo("[3/4] Skipping AI analysis (--no-ai mode)")
        batch_summary = {
            "overall_risk": "unknown",
            "summary": "AI analysis was skipped. Review findings manually.",
            "critical_issues": [],
            "recommendations_priority": [],
            "contract_hardening_suggestions": [],
        }

    # Step 4: Score and generate report
    click.echo("[4/4] Generating report...")
    scorer = SeverityScorer()
    scored_results = scorer.rank_findings(findings)
    stats = scorer.summary_stats(scored_results)

    report_config = config.get("reports", {})
    report_config["output_dir"] = output
    generator = ReportGenerator(report_config)

    generated = generator.generate(
        findings=findings,
        batch_summary=batch_summary,
        scored_results=scored_results,
        contract_info=contract_info,
    )

    elapsed = time.time() - start_time

    # Print summary to console
    click.echo("\n" + "=" * 60)
    click.echo("SCAN SUMMARY")
    click.echo("=" * 60)
    click.echo(f"Contract:       {contract_info.get('contract_name', 'Unknown')}")
    click.echo(f"Total findings: {stats['total_findings']}")
    click.echo(f"Confirmed:      {stats['confirmed_vulnerabilities']}")
    click.echo(f"False positives:{stats['false_positives']}")
    click.echo(f"Average score:  {stats['avg_score']}")
    click.echo(f"Elapsed time:   {elapsed:.1f}s")
    click.echo("")
    click.echo("By severity:")
    for sev, count in stats["by_severity"].items():
        if count > 0:
            click.echo(f"  {sev.upper():10s}: {count}")
    click.echo("")

    # Print top findings
    click.echo("Top findings:")
    for i, (finding, result) in enumerate(scored_results[:5], 1):
        sev = result["severity"].value.upper()
        status = "CONFIRMED" if result["is_confirmed"] else "PENDING"
        click.echo(
            f"  {i}. [{sev}] {finding.vuln_type} "
            f"@ line {finding.line} "
            f"(score: {result['score']:.3f}, {status})"
        )
    click.echo("")

    # Print report paths
    click.echo("Reports generated:")
    for fmt, path in generated.items():
        click.echo(f"  {fmt.upper()}: {path}")
    click.echo("")


@cli.command()
@click.option("--address", "-a", required=True, help="Contract address")
@click.option("--chain", default="ethereum", help="Chain name")
@click.pass_context
def fetch(ctx, address, chain):
    """Fetch and display contract source code info (without scanning)."""
    config = ctx.obj["config"]
    chain_config = config.get("chains", {})
    fetcher = MultiChainFetcher(chain_config)

    click.echo(f"Fetching {address} from {chain}...")
    source, metadata = fetcher.fetch(address, chain=chain)

    if source:
        click.echo(f"Contract: {metadata.get('contract_name', 'Unknown')}")
        click.echo(f"Compiler: {metadata.get('compiler_version', 'Unknown')}")
        click.echo(f"Source length: {len(source)} chars")
        click.echo(f"\n--- Source Code (first 500 chars) ---")
        click.echo(source[:500])
        if len(source) > 500:
            click.echo(f"... ({len(source) - 500} more chars)")
    else:
        click.echo(f"Failed: {metadata.get('error', 'unknown error')}")


@cli.command()
@click.pass_context
def chains(ctx):
    """List supported chains and their configuration status."""
    config = ctx.obj["config"]
    chain_config = config.get("chains", {})
    fetcher = MultiChainFetcher(chain_config)

    click.echo("Supported chains:")
    click.echo("")
    for chain_name in fetcher.list_chains():
        info = fetcher.get_chain_info(chain_name)
        api_key_status = "configured" if info["has_api_key"] else "NOT SET"
        click.echo(
            f"  {chain_name:12s} "
            f"(chain_id: {info['chain_id']}) "
            f"API key: {api_key_status}"
        )


if __name__ == "__main__":
    cli()
