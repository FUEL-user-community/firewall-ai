#!/usr/bin/env python3
"""
run_card.py — One-Shot Card Runner CLI

Usage:
    python scripts/run_card.py --list                    # Show all available cards
    python scripts/run_card.py operational_resilience     # Run a single card
    python scripts/run_card.py SY-09                      # Run by card ID
    python scripts/run_card.py all                        # Run every card once

Runs directly against the card engine — no server required.
"""

import sys
import os
import json
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Load .env
from dotenv import load_dotenv
load_dotenv()

# UTF-8 Encoding Fix for Windows Consoles
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def list_cards():
    """Print all available card definitions."""
    from core.engine.card_runner import CardRunner
    cards = CardRunner.load_cards()

    print(f"\n{'═' * 70}")
    print(f"  CORE DEFENSE — Card Registry ({len(cards)} cards)")
    print(f"{'═' * 70}\n")
    print(f"  {'ID':<8} {'KEY':<30} {'SCHEDULE':<12} {'SEVERITY':<10}")
    print(f"  {'─' * 8} {'─' * 30} {'─' * 12} {'─' * 10}")

    for key, card in cards.items():
        card_id = card.get("id", "?")
        schedule = card.get("schedule", "?")
        severity = card.get("severity", "normal")
        print(f"  {card_id:<8} {key:<30} {schedule:<12} {severity:<10}")

    print(f"\n  Run a card:  python scripts/run_card.py <card_key>")
    print(f"  Example:     python scripts/run_card.py operational_resilience\n")


def find_card_key(identifier: str) -> str:
    """Resolve a card key from either a key name or card ID (e.g., 'SY-09')."""
    from core.engine.card_runner import CardRunner
    cards = CardRunner.load_cards()

    # Direct key match
    if identifier in cards:
        return identifier

    # Match by card ID (e.g., "SY-09")
    for key, card in cards.items():
        if card.get("id", "").upper() == identifier.upper():
            return key

    return None


def run_card(card_key: str):
    """Execute a single card and pretty-print the result."""
    from core.engine.card_runner import CardRunner

    runner = CardRunner()
    card_def = runner.get_card_def(card_key)
    card_id = card_def.get("id", card_key)
    card_name = card_def.get("name", card_key)
    tools = card_def.get("tool_chain") or []

    print(f"\n{'═' * 70}")
    print(f"  ▶ Running: {card_id} — {card_name}")
    print(f"  Tools: {', '.join(tools) if tools else '(none — LLM reasoning only)'}")
    print(f"{'═' * 70}\n")

    start = time.time()
    result = runner.execute(card_key)
    elapsed = time.time() - start

    if result:
        sev = result.severity.upper()
        sev_icon = {"CRITICAL": "🔴", "CAUTION": "🟡", "NORMAL": "🟢"}.get(sev, "⚪")

        # Trust score indicator
        ts = result.trust_score
        if ts >= 0.7:
            trust_icon = "🟢"
        elif ts >= 0.5:
            trust_icon = "🟡"
        else:
            trust_icon = "🔴"

        print(f"  {sev_icon} Severity: {sev}")
        print(f"  {trust_icon} Trust Score: {ts:.0%}")
        print(f"  📋 Title: {result.title}")
        print(f"  ⏱  Elapsed: {elapsed:.1f}s")

        # Reasoning trace (thought chain forensics)
        if result.reasoning_trace:
            print(f"\n  🧠 Reasoning Trace ({len(result.reasoning_trace)} steps):")
            print(f"  {'─' * 60}")
            for i, step in enumerate(result.reasoning_trace, 1):
                print(f"    {i}. {step}")

        print(f"\n  Finding:")
        print(f"  {'─' * 60}")
        for line in result.finding.split('\n'):
            print(f"    {line}")

        if result.evidence:
            print(f"\n  Evidence ({len(result.evidence)} items):")
            print(f"  {'─' * 60}")
            for e in result.evidence:
                print(f"    • {e}")

        if result.metrics:
            print(f"\n  Metrics:")
            print(f"  {'─' * 60}")
            for k, v in result.metrics.items():
                print(f"    {k}: {v}")

        # Trust warning
        if ts < 0.7:
            print(f"\n  ⚠️  TRUST WARNING: {int((1-ts)*100)}% of evidence claims could not be verified")
            print(f"      against raw tool output. Review findings manually.")

        print(f"\n  Full JSON:")
        print(f"  {'─' * 60}")
        full = {
            "card_id": result.card_id,
            "severity": result.severity,
            "trust_score": result.trust_score,
            "title": result.title,
            "finding": result.finding,
            "reasoning_trace": result.reasoning_trace,
            "evidence": result.evidence,
            "metrics": result.metrics,
        }
        print(json.dumps(full, indent=2))
    else:
        print(f"  ⚪ Not triggered (no alert condition met) or deduplicated.")
        print(f"  ⏱  Elapsed: {elapsed:.1f}s")

    print()


def run_all():
    """Run every card once, sequentially."""
    from core.engine.card_runner import CardRunner
    cards = CardRunner.load_cards()

    print(f"\n{'═' * 70}")
    print(f"  Running ALL {len(cards)} cards...")
    print(f"{'═' * 70}\n")

    triggered = 0
    failed = 0
    for key in cards:
        try:
            run_card(key)
            triggered += 1
        except Exception as e:
            print(f"\n  [ERROR] Card '{key}' failed: {e}\n")
            failed += 1

    print(f"\n  Done — {triggered} cards executed, {failed} failed.\n")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("--help", "-h"):
        print(__doc__)
        return

    arg = sys.argv[1]

    if arg == "--list":
        list_cards()
        return

    if arg == "all":
        run_all()
        return

    # Resolve card key
    card_key = find_card_key(arg)
    if not card_key:
        print(f"\n  x Card '{arg}' not found.\n")
        list_cards()
        return

    run_card(card_key)


if __name__ == "__main__":
    main()
