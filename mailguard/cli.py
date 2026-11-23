"""Command Line Interface (CLI) and core analysis orchestrator for MailGuard."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

from rich.console import Console

from mailguard.dmarc_check import DMARCChecker
from mailguard.dkim_check import DKIMChecker
from mailguard.dns_resolver import BaseDNSResolver, get_resolver
from mailguard.enrichment import ThreatEnricher
from mailguard.heuristics import HeuristicEngine
from mailguard.mitre import MITREMapper
from mailguard.models import (
    AnalysisResult,
    Verdict,
)
from mailguard.parser import EmailParser
from mailguard.report import ReportGenerator
from mailguard.scorer import RiskScorer
from mailguard.spf_check import SPFChecker
from mailguard.splunk_forwarder import SplunkForwarder
from mailguard.utils import load_config

logger = logging.getLogger("mailguard")


class MailGuardAnalyzer:
    """Orchestrates end-to-end email authentication, heuristic inspection, and SOC reporting."""

    def __init__(
        self,
        offline: bool = False,
        fixtures_path: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
        enable_enrichment: bool = False,
    ):
        self.config = config or load_config()
        self.offline = offline
        self.fixtures_path = fixtures_path

        # 1. Initialize DNS Resolver
        self.resolver = get_resolver(
            offline=offline,
            fixtures_path=fixtures_path,
            config=self.config,
        )

        # 2. Initialize Core Engines
        self.parser = EmailParser(self.config)
        self.spf_checker = SPFChecker(
            resolver=self.resolver,
            trusted_receivers=self.config.get("trusted_receivers", []),
        )
        self.dkim_checker = DKIMChecker(resolver=self.resolver)
        self.dmarc_checker = DMARCChecker(resolver=self.resolver)
        self.heuristics_engine = HeuristicEngine(self.config)
        self.scorer = RiskScorer(self.config)
        self.mitre_mapper = MITREMapper()
        self.enricher = ThreatEnricher(self.config) if enable_enrichment else None
        self.forwarder = SplunkForwarder(self.config)
        self.reporter = ReportGenerator()

    def analyze_file(
        self,
        file_path: str | Path,
        send_to_splunk: bool = False,
    ) -> AnalysisResult:
        """Analyze a single raw .eml file."""
        parsed = self.parser.parse_file(file_path)
        return self._run_pipeline(parsed, send_to_splunk=send_to_splunk)

    def analyze_bytes(
        self,
        raw_bytes: bytes,
        send_to_splunk: bool = False,
    ) -> AnalysisResult:
        """Analyze email directly from raw bytes."""
        parsed = self.parser.parse_bytes(raw_bytes)
        return self._run_pipeline(parsed, send_to_splunk=send_to_splunk)

    def _run_pipeline(self, parsed: Any, send_to_splunk: bool = False) -> AnalysisResult:
        # Step 1: SPF Evaluation
        spf_res = self.spf_checker.evaluate(parsed)

        # Step 2: DKIM Verification
        dkim_res = self.dkim_checker.evaluate(parsed)

        # Step 3: DMARC Policy & Alignment Evaluation
        dmarc_res, align_res = self.dmarc_checker.evaluate(parsed, spf_res, dkim_res)

        # Step 4: Heuristic Risk Detection
        heuristics = self.heuristics_engine.analyze(parsed)

        # Step 5: Composite Risk Scoring & Verdict
        score, verdict, top_reasons = self.scorer.calculate(
            spf=spf_res,
            dkim=dkim_res,
            dmarc=dmarc_res,
            alignment=align_res,
            heuristics=heuristics,
        )
        recommended_action = self.scorer.derive_recommended_action(
            verdict=verdict,
            heuristics=heuristics,
            attachments=parsed.attachments,
        )

        # Step 6: MITRE ATT&CK Mapping
        mitre_techs = self.mitre_mapper.map_evidence(
            spf=spf_res,
            dkim=dkim_res,
            dmarc=dmarc_res,
            alignment=align_res,
            heuristics=heuristics,
        )

        # Step 7: Optional Enrichment
        enrichment_results = []
        if self.enricher and self.enricher.is_configured():
            if parsed.candidate_originating_ip:
                ip_res = self.enricher.lookup_ip(parsed.candidate_originating_ip)
                if ip_res:
                    enrichment_results.append(ip_res)
            for att in parsed.attachments:
                h_res = self.enricher.lookup_file_hash(att.sha256)
                if h_res:
                    enrichment_results.append(h_res)

        now_utc = datetime.now(timezone.utc).isoformat()
        result = AnalysisResult(
            timestamp=now_utc,
            message_id=parsed.message_id,
            subject=parsed.subject,
            from_address=parsed.from_address,
            from_domain=parsed.from_domain,
            return_path=parsed.return_path,
            return_path_domain=parsed.return_path_domain,
            originating_ip=parsed.candidate_originating_ip,
            recipients=parsed.to_addresses + parsed.cc_addresses,
            spf=spf_res,
            dkim=dkim_res,
            dmarc=dmarc_res,
            alignment=align_res,
            heuristics=heuristics,
            risk_score=score,
            verdict=verdict,
            recommended_action=recommended_action,
            top_reasons=top_reasons,
            mitre_techniques=mitre_techs,
            urls=parsed.urls,
            attachments=parsed.attachments,
            enrichment_results=enrichment_results,
        )

        # Step 8: Persistence & Splunk HEC Ingestion
        self.forwarder.persist_locally(result)
        if send_to_splunk:
            success, msg = self.forwarder.forward_to_splunk(result)
            if not success:
                logger.warning(f"Splunk delivery failed: {msg}")

        return result


def main() -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="mailguard",
        description="MailGuard: Defensive Email Authentication & Spoofing Analyzer",
    )
    parser.add_argument("--config", "-c", help="Path to custom config.yaml")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debug logging")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: analyze
    p_analyze = subparsers.add_parser("analyze", help="Analyze a single .eml email file")
    p_analyze.add_argument("file", help="Path to raw .eml file")
    p_analyze.add_argument("--offline", action="store_true", help="Run in strict offline mode without network queries")
    p_analyze.add_argument("--fixtures", help="Path to local DNS fixtures JSON file")
    p_analyze.add_argument("--send-to-splunk", action="store_true", help="Forward event to Splunk HEC")
    p_analyze.add_argument("--format", choices=["table", "json", "html"], default="table", help="Output format")
    p_analyze.add_argument("--output", "-o", help="Write report to output file")
    p_analyze.add_argument("--enrich", action="store_true", help="Enable optional threat intelligence enrichment")

    # Command: analyze-dir
    p_dir = subparsers.add_parser("analyze-dir", help="Analyze all .eml files in a directory")
    p_dir.add_argument("directory", help="Directory containing .eml files")
    p_dir.add_argument("--recursive", "-r", action="store_true", help="Search recursively")
    p_dir.add_argument("--offline", action="store_true", help="Run in strict offline mode")
    p_dir.add_argument("--fixtures", help="Path to local DNS fixtures JSON file")
    p_dir.add_argument("--send-to-splunk", action="store_true", help="Forward all events to Splunk HEC")
    p_dir.add_argument("--format", choices=["table", "json", "html"], default="table", help="Output format")
    p_dir.add_argument("--output", "-o", help="Write report or summary to file")

    # Command: web
    p_web = subparsers.add_parser("web", help="Launch local Flask SOC web interface")
    p_web.add_argument("--port", type=int, default=5000, help="Web port (default: 5000)")
    p_web.add_argument("--host", default="127.0.0.1", help="Host interface (default: 127.0.0.1)")
    p_web.add_argument("--offline", action="store_true", help="Run web UI with offline DNS resolver")
    p_web.add_argument("--fixtures", help="Path to local DNS fixtures JSON file")

    args = parser.parse_args()

    # Logging setup
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    console = Console()

    if not args.command:
        parser.print_help()
        return 0

    cfg = load_config(args.config)

    if args.command == "analyze":
        analyzer = MailGuardAnalyzer(
            offline=args.offline,
            fixtures_path=args.fixtures,
            config=cfg,
            enable_enrichment=args.enrich,
        )

        try:
            result = analyzer.analyze_file(args.file, send_to_splunk=args.send_to_splunk)
        except Exception as e:
            console.print(f"[bold red]Analysis failed:[/bold red] {e}")
            return 1

        if args.format == "json":
            json_str = analyzer.reporter.generate_json(result)
            if args.output:
                Path(args.output).write_text(json_str, encoding="utf-8")
                console.print(f"[green]JSON report written to {args.output}[/green]")
            else:
                print(json_str)
        elif args.format == "html":
            out_path = args.output or "output/report.html"
            analyzer.reporter.generate_html(result, output_path=out_path)
            console.print(f"[green]HTML report written to {out_path}[/green]")
        else:
            analyzer.reporter.render_terminal(result)

        return 0

    elif args.command == "analyze-dir":
        analyzer = MailGuardAnalyzer(
            offline=args.offline,
            fixtures_path=args.fixtures,
            config=cfg,
        )

        dir_path = Path(args.directory)
        if not dir_path.is_dir():
            console.print(f"[bold red]Directory not found:[/bold red] {args.directory}")
            return 1

        pattern = "**/*.eml" if args.recursive else "*.eml"
        eml_files = sorted(list(dir_path.glob(pattern)))

        if not eml_files:
            console.print(f"[yellow]No .eml files found in {args.directory}[/yellow]")
            return 0

        results: List[AnalysisResult] = []
        for f in eml_files:
            try:
                res = analyzer.analyze_file(f, send_to_splunk=args.send_to_splunk)
                results.append(res)
            except Exception as e:
                logger.error(f"Error analyzing {f}: {e}")

        if args.format == "json":
            json_data = [r.to_dict() for r in results]
            json_str = json.dumps(json_data, indent=2)
            if args.output:
                Path(args.output).write_text(json_str, encoding="utf-8")
                console.print(f"[green]Batch JSON summary written to {args.output}[/green]")
            else:
                print(json_str)
        elif args.format == "html":
            out_path = args.output or "output/batch_report.html"
            # Render first or batch HTML
            if results:
                analyzer.reporter.generate_html(results[0], output_path=out_path)
            console.print(f"[green]Batch HTML written to {out_path}[/green]")
        else:
            analyzer.reporter.render_directory_table(results)

        return 0

    elif args.command == "web":
        from mailguard.web import create_app
        app = create_app(
            offline=args.offline,
            fixtures_path=args.fixtures,
            config=cfg,
        )
        console.print(f"[bold cyan]Launching MailGuard SOC Web Interface at http://{args.host}:{args.port}[/bold cyan]")
        app.run(host=args.host, port=args.port, debug=False)
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
