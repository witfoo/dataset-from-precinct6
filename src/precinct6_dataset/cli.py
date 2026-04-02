"""Command-line interface for the Precinct6 Dataset Generator.

Usage:
    precinct6-dataset extract [--orgs ORG1 ORG2 ...] [--workers N] [--days N]
    precinct6-dataset sanitize [--skip-ml] [--skip-claude] [--no-sanitize] [--workers N]
    precinct6-dataset label
    precinct6-dataset export [--format signal|graph|all] [--shard-size N]
    precinct6-dataset verify
    precinct6-dataset pipeline [all flags above]
    precinct6-dataset monitor [--interval N]
    precinct6-dataset converge [--max-cycles N] [--ml-sample N]
    precinct6-dataset status
"""

import argparse
import sys

from precinct6_dataset import __version__


def cmd_extract(args):
    """Extract data from Cassandra."""
    from precinct6_dataset.config import validate_config, KNOWN_ORGS
    validate_config(require_cassandra=True)

    orgs = args.orgs or list(KNOWN_ORGS.keys())
    if not orgs:
        print("Error: No organizations specified. Use --orgs or configure customer_config.json",
              file=sys.stderr)
        sys.exit(1)

    from precinct6_dataset.extract import extract_all
    extract_all(orgs=orgs, workers=args.workers, max_days=args.days)


def cmd_sanitize(args):
    """Run the sanitization pipeline."""
    from pathlib import Path
    from precinct6_dataset.config import validate_config, RAW_DIR, SANITIZED_DIR

    if not args.no_sanitize and args.claude:
        validate_config(require_anthropic=True)

    from precinct6_dataset.registry import PIIRegistry
    from precinct6_dataset.sanitize import SanitizationPipeline

    registry = PIIRegistry()
    pipeline = SanitizationPipeline(
        registry=registry,
        use_ml=not args.skip_ml and not args.no_sanitize,
        use_claude=args.claude and not args.no_sanitize,
        raw_dir=RAW_DIR,
        output_dir=SANITIZED_DIR,
        ml_sample_size=args.ml_sample,
        sanitize=not args.no_sanitize,
    )
    pipeline.run()


def cmd_label(args):
    """Attach security labels to sanitized data."""
    from precinct6_dataset.config import SANITIZED_DIR
    from precinct6_dataset.label import Labeler

    labeler = Labeler(sanitized_dir=SANITIZED_DIR)
    labeler.build_index()
    labeler.label_all()


def cmd_export(args):
    """Export to final dataset formats."""
    from precinct6_dataset.config import SANITIZED_DIR, OUTPUT_DIR

    fmt = args.format or "all"

    if fmt in ("signal", "all"):
        from precinct6_dataset.export_signal import SignalExporter
        sig = SignalExporter(
            sanitized_dir=SANITIZED_DIR,
            output_dir=OUTPUT_DIR / "signal",
            shard_size=args.shard_size,
        )
        sig.export_all()

    if fmt in ("graph", "all"):
        from precinct6_dataset.export_graph import GraphExporter
        graph = GraphExporter(
            sanitized_dir=SANITIZED_DIR,
            output_dir=OUTPUT_DIR / "graph",
        )
        graph.export_all()


def cmd_verify(args):
    """Verify sanitized output for PII leaks."""
    from precinct6_dataset.config import SANITIZED_DIR
    from precinct6_dataset.registry import PIIRegistry
    from precinct6_dataset.verify import Verifier

    registry = PIIRegistry()
    verifier = Verifier(registry=registry, sanitized_dir=SANITIZED_DIR)
    results = verifier.run_all_checks()
    print(f"\nViolations: {results.get('violations', 0)}")
    print(f"Warnings: {results.get('warnings', 0)}")


def cmd_pipeline(args):
    """Run the full end-to-end pipeline."""
    print("=== Precinct6 Dataset Pipeline ===\n")

    if not args.skip_extract:
        print("[1/5] Extracting from Cassandra...")
        cmd_extract(args)

    print("\n[2/5] Sanitizing...")
    cmd_sanitize(args)

    print("\n[3/5] Labeling...")
    cmd_label(args)

    print("\n[4/5] Exporting...")
    cmd_export(args)

    print("\n[5/5] Verifying...")
    cmd_verify(args)

    print("\n=== Pipeline Complete ===")


def cmd_monitor(args):
    """Real-time monitoring dashboard."""
    try:
        from precinct6_dataset.monitor import PipelineMonitor
    except ImportError:
        print("Monitor requires the 'rich' package. Install with: pip install precinct6-dataset[monitor]",
              file=sys.stderr)
        sys.exit(1)

    monitor = PipelineMonitor(interval=args.interval)
    monitor.run()


def cmd_converge(args):
    """Run sanitization cycles until convergence."""
    from precinct6_dataset.config import SANITIZED_DIR, RAW_DIR
    from precinct6_dataset.registry import PIIRegistry
    from precinct6_dataset.sanitize import SanitizationPipeline

    registry = PIIRegistry()
    max_cycles = args.max_cycles

    for cycle in range(1, max_cycles + 1):
        before = sum(registry.stats().values())
        print(f"\n{'='*60}")
        print(f"CYCLE {cycle}: registry={before:,} entries")
        print(f"{'='*60}")

        pipeline = SanitizationPipeline(
            registry=registry,
            use_ml=True,
            use_claude=args.claude,
            raw_dir=RAW_DIR,
            output_dir=SANITIZED_DIR,
            ml_sample_size=args.ml_sample,
        )
        pipeline.run()

        after = sum(registry.stats().values())
        delta = after - before
        print(f"Cycle {cycle} complete: {before:,} -> {after:,} (+{delta})")

        if delta == 0:
            print(f"\nCONVERGED after {cycle} cycles!")
            break
    else:
        print(f"\nReached max cycles ({max_cycles}). Final delta: {delta}")


def cmd_status(args):
    """Show pipeline status."""
    from precinct6_dataset.config import DATA_DIR, SANITIZED_DIR, OUTPUT_DIR, REGISTRY_DB_PATH
    from pathlib import Path

    print("=== Precinct6 Dataset Status ===\n")

    # Registry
    if REGISTRY_DB_PATH.exists():
        from precinct6_dataset.registry import PIIRegistry
        r = PIIRegistry()
        stats = r.stats()
        print(f"PII Registry: {sum(stats.values()):,} entries")
        for cat, count in sorted(stats.items(), key=lambda x: -x[1])[:5]:
            print(f"  {cat}: {count:,}")
        r.close()
    else:
        print("PII Registry: not created yet")

    # Data files
    for label, d in [("Raw", DATA_DIR / "raw"), ("Sanitized", SANITIZED_DIR), ("Output", OUTPUT_DIR)]:
        if d.exists():
            files = list(d.rglob("*.jsonl")) + list(d.rglob("*.parquet"))
            total_size = sum(f.stat().st_size for f in files)
            print(f"\n{label}: {len(files)} files, {total_size / 1e9:.1f} GB")
        else:
            print(f"\n{label}: not created yet")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="precinct6-dataset",
        description="Generate labeled cybersecurity datasets from WitFoo Precinct 6.x",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # extract
    p_extract = subparsers.add_parser("extract", help="Extract data from Cassandra")
    p_extract.add_argument("--orgs", nargs="+", help="Organization slugs to extract")
    p_extract.add_argument("--workers", type=int, default=4, help="Parallel extraction workers (default: 4)")
    p_extract.add_argument("--days", type=int, default=0, help="Max time periods to extract per org (0=all)")

    # sanitize
    p_sanitize = subparsers.add_parser("sanitize", help="Sanitize extracted data")
    p_sanitize.add_argument("--skip-ml", action="store_true", help="Skip ML/NER layer (Layer 3)")
    p_sanitize.add_argument("--claude", action="store_true", help="Enable Claude AI review (Layer 4)")
    p_sanitize.add_argument("--no-sanitize", action="store_true", help="Skip all sanitization (pass-through mode)")
    p_sanitize.add_argument("--ml-sample", type=int, default=2000, help="ML sample size (default: 2000)")
    p_sanitize.add_argument("--workers", type=int, default=1, help="Parallel sanitization workers")

    # label
    p_label = subparsers.add_parser("label", help="Attach security labels")

    # export
    p_export = subparsers.add_parser("export", help="Export to final formats")
    p_export.add_argument("--format", choices=["signal", "graph", "all"], default="all",
                         help="Output format (default: all)")
    p_export.add_argument("--shard-size", type=int, default=5_000_000,
                         help="Parquet shard size in rows (default: 5M)")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify sanitized output")

    # pipeline
    p_pipeline = subparsers.add_parser("pipeline", help="Run full end-to-end pipeline")
    p_pipeline.add_argument("--orgs", nargs="+", help="Organization slugs to extract")
    p_pipeline.add_argument("--workers", type=int, default=4, help="Parallel workers")
    p_pipeline.add_argument("--days", type=int, default=0, help="Max time periods per org")
    p_pipeline.add_argument("--skip-extract", action="store_true", help="Skip extraction step")
    p_pipeline.add_argument("--skip-ml", action="store_true", help="Skip ML/NER layer")
    p_pipeline.add_argument("--claude", action="store_true", help="Enable Claude AI review")
    p_pipeline.add_argument("--no-sanitize", action="store_true", help="Skip all sanitization")
    p_pipeline.add_argument("--ml-sample", type=int, default=2000, help="ML sample size")
    p_pipeline.add_argument("--format", choices=["signal", "graph", "all"], default="all")
    p_pipeline.add_argument("--shard-size", type=int, default=5_000_000)

    # monitor
    p_monitor = subparsers.add_parser("monitor", help="Real-time monitoring dashboard")
    p_monitor.add_argument("--interval", type=int, default=3, help="Update interval in seconds")

    # converge
    p_converge = subparsers.add_parser("converge", help="Run sanitization until convergence")
    p_converge.add_argument("--max-cycles", type=int, default=10, help="Maximum convergence cycles")
    p_converge.add_argument("--ml-sample", type=int, default=2000, help="ML sample size per cycle")
    p_converge.add_argument("--claude", action="store_true", help="Enable Claude review in cycles")

    # status
    p_status = subparsers.add_parser("status", help="Show pipeline status")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    commands = {
        "extract": cmd_extract,
        "sanitize": cmd_sanitize,
        "label": cmd_label,
        "export": cmd_export,
        "verify": cmd_verify,
        "pipeline": cmd_pipeline,
        "monitor": cmd_monitor,
        "converge": cmd_converge,
        "status": cmd_status,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
