"""
AI layer tests for Network Threat Visualizer.

Levels:
  1. Offline tests  -- no API key required (imports, prompt building, config)
  2. Online tests   -- require ANTHROPIC_API_KEY in the environment

Run all:          python test_ai.py
Offline only:     python test_ai.py --offline
Single alert:     python test_ai.py --single <type>
    types: port_scan | ddos | brute_force | exfiltration
"""

import sys, os, json, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


# ── helpers ──────────────────────────────────────────────────────────────────

def sep(title=""):
    print("\n" + "=" * 70)
    if title:
        print(f"  {title}")
        print("=" * 70)

def ok(label):
    print(f"  [PASS] {label}")

def fail(label, detail=""):
    print(f"  [FAIL] {label}")
    if detail:
        print(f"         {detail}")

def check(condition, label, detail=""):
    if condition:
        ok(label)
    else:
        fail(label, detail)
    return condition


# ── offline tests (no API key) ────────────────────────────────────────────────

def test_imports():
    sep("TEST 1: Imports & Config")
    try:
        from ai import ai_config
        ok("ai_config imported")
        check(ai_config.MODEL == "claude-opus-4-7", f"Model is claude-opus-4-7 (got {ai_config.MODEL})")
        check(ai_config.REQUESTS_PER_MINUTE == 20, "Rate limit is 20 req/min")
        check(ai_config.MAX_RETRIES == 3, "Max retries is 3")
    except Exception as e:
        fail("ai_config import", str(e))
        return False

    try:
        from ai import prompt_templates
        ok("prompt_templates imported")
        check(len(prompt_templates.SYSTEM_PROMPT) > 1000, "SYSTEM_PROMPT is substantial (>1000 chars)")
    except Exception as e:
        fail("prompt_templates import", str(e))
        return False

    try:
        from ai import AIAnalyzer, AlertAnalysis, ReportGenerator
        ok("AIAnalyzer, AlertAnalysis, ReportGenerator importable from ai package")
    except Exception as e:
        fail("ai package __init__ imports", str(e))
        return False

    return True


def test_prompt_building():
    sep("TEST 2: Prompt Building (no API key)")
    from traffic_simulator import TrafficSimulator
    from detectors import DetectionEngine
    from ai import prompt_templates

    sim = TrafficSimulator()
    engine = DetectionEngine()
    scenarios = {
        "port_scan":   sim.generate_port_scan(port_count=200),
        "ddos":        sim.generate_ddos(duration_seconds=4, packets_per_second=1000),
        "brute_force": sim.generate_brute_force(attempts=50),
        "exfiltration": sim.generate_data_exfiltration(size_mb=10),
    }

    all_pass = True
    for name, packets in scenarios.items():
        alerts = engine.process_packets(packets)
        engine.reset()
        if not alerts:
            fail(f"{name}: detector produced no alert (check detector thresholds)")
            all_pass = False
            continue

        alert = alerts[0]
        try:
            prompt = prompt_templates.build_alert_prompt(alert)
            check(len(prompt) > 50, f"{name}: prompt built ({len(prompt)} chars)")
            check(alert.alert_id in prompt, f"{name}: alert_id present in prompt")
        except Exception as e:
            fail(f"{name}: prompt building raised {e}")
            all_pass = False

    return all_pass


# ── online tests (require API key) ───────────────────────────────────────────

def test_single_alert(alert_type: str = "port_scan"):
    sep(f"TEST 3: Single Alert Analysis ({alert_type})")
    from ai import ai_config
    if not ai_config.ANTHROPIC_API_KEY:
        fail("ANTHROPIC_API_KEY not set — skipping online test")
        return False

    from traffic_simulator import TrafficSimulator
    from detectors import DetectionEngine
    from ai import AIAnalyzer

    sim = TrafficSimulator()
    engine = DetectionEngine()
    generators = {
        "port_scan":   lambda: sim.generate_port_scan(port_count=200),
        "ddos":        lambda: sim.generate_ddos(duration_seconds=4, packets_per_second=1000),
        "brute_force": lambda: sim.generate_brute_force(attempts=50),
        "exfiltration": lambda: sim.generate_data_exfiltration(size_mb=10),
    }

    if alert_type not in generators:
        fail(f"Unknown type '{alert_type}'. Choose: {list(generators)}")
        return False

    alerts = engine.process_packets(generators[alert_type]())
    if not alerts:
        fail("Detector produced no alert")
        return False

    alert = alerts[0]
    print(f"\n  Alert: [{alert.severity.value.upper()}] {alert.alert_type.value}")
    print(f"  ID:    {alert.alert_id}")

    analyzer = AIAnalyzer()
    print("\n  Calling Claude API...")
    analysis = analyzer.analyze_alert(alert)

    if analysis.error:
        fail(f"Analysis returned error: {analysis.error}")
        return False

    ok("Analysis returned without error")
    check(len(analysis.threat_assessment) > 20, "threat_assessment populated")
    check(len(analysis.recommended_actions) >= 1, f"recommended_actions has {len(analysis.recommended_actions)} item(s)")
    check(analysis.false_positive_likelihood in ("low", "medium", "high"), f"false_positive_likelihood: {analysis.false_positive_likelihood}")
    check(analysis.priority in ("immediate", "high", "medium", "low"), f"priority: {analysis.priority}")

    print(f"\n  --- AI Output ---")
    print(f"  Threat:    {analysis.threat_assessment[:120]}...")
    print(f"  Priority:  {analysis.priority}")
    print(f"  FP risk:   {analysis.false_positive_likelihood}")
    print(f"  Actions:   {len(analysis.recommended_actions)}")
    for action in analysis.recommended_actions:
        print(f"    • {action}")
    print(f"  Tokens:    {analysis.tokens_used} total / {analysis.cache_read_tokens} from cache")
    return True


def test_batch_and_report():
    sep("TEST 4: Batch Analysis + Report Generation")
    from ai import ai_config
    if not ai_config.ANTHROPIC_API_KEY:
        fail("ANTHROPIC_API_KEY not set — skipping online test")
        return False

    from traffic_simulator import TrafficSimulator
    from detectors import DetectionEngine
    from ai import AIAnalyzer
    from ai.report_generator import ReportGenerator

    sim = TrafficSimulator()
    engine = DetectionEngine()
    packets = sim.generate_mixed_scenario()
    all_alerts = engine.process_packets(packets)

    if not all_alerts:
        fail("Mixed scenario produced no alerts")
        return False

    # Cap at 4 alerts to keep test fast and cheap
    alerts = all_alerts[:4]
    print(f"\n  Analyzing {len(alerts)} alert(s) from mixed scenario...")

    analyzer = AIAnalyzer()
    analyses = analyzer.analyze_batch(alerts)

    ok(f"Batch complete: {len(analyses)} analyses")
    errors = [a for a in analyses if a.error]
    check(len(errors) == 0, f"No errors in batch ({len(errors)} errors)")

    total_tokens = sum(a.tokens_used for a in analyses)
    cached_tokens = sum(a.cache_read_tokens for a in analyses)
    print(f"  Total tokens used:   {total_tokens:,}")
    print(f"  Tokens from cache:   {cached_tokens:,}")
    if total_tokens > 0:
        cache_pct = round(cached_tokens / total_tokens * 100)
        print(f"  Cache hit rate:      {cache_pct}%")

    print("\n  Generating report...")
    reporter = ReportGenerator()
    report = reporter.generate_report(alerts, analyses)

    check(len(report) > 500, f"Report generated ({len(report)} chars)")
    check("# Network Security Report" in report, "Report has correct title")
    check("## Executive Summary" in report, "Report has Executive Summary section")
    check("## Consolidated Recommended Actions" in report, "Report has Recommended Actions section")

    report_path = os.path.join(os.path.dirname(__file__), "test_report.md")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)
    ok(f"Report saved to test_report.md")

    return True


def test_fallback_no_key():
    sep("TEST 5: Fallback Analysis (simulated API failure)")
    from traffic_simulator import TrafficSimulator
    from detectors import PortScanDetector
    from ai.ai_analyzer import AIAnalyzer, AlertAnalysis

    sim = TrafficSimulator()
    d = PortScanDetector(window_seconds=10, port_threshold=50)
    alerts = [a for p in sim.generate_port_scan(port_count=100) for a in [d.process(p)] if a]
    if not alerts:
        fail("No alert to test fallback with")
        return False

    fallback = AIAnalyzer._fallback_analysis(alerts[0], "simulated_error")
    check(isinstance(fallback, AlertAnalysis), "Fallback returns AlertAnalysis")
    check(fallback.error == "simulated_error", "Fallback preserves error string")
    check(len(fallback.recommended_actions) >= 1, "Fallback has at least one action")
    check(fallback.priority in ("high", "medium", "low", "immediate"), f"Fallback priority valid: {fallback.priority}")
    return True


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Test AI layer for Network Threat Visualizer")
    parser.add_argument("--offline", action="store_true", help="Run offline tests only (no API key needed)")
    parser.add_argument("--single", metavar="TYPE", help="Test a single alert type: port_scan|ddos|brute_force|exfiltration")
    args = parser.parse_args()

    sep("NETWORK THREAT VISUALIZER -- AI Layer Tests")

    from ai import ai_config
    key_set = bool(ai_config.ANTHROPIC_API_KEY)
    print(f"\n  ANTHROPIC_API_KEY: {'SET' if key_set else 'NOT SET'}")
    if not key_set:
        print("  Online tests will be skipped. Set the key to run them:")
        print("    Windows CMD:   set ANTHROPIC_API_KEY=sk-ant-...")
        print("    PowerShell:    $env:ANTHROPIC_API_KEY='sk-ant-...'")
        print("    Bash/Git Bash: export ANTHROPIC_API_KEY=sk-ant-...")

    results = []
    results.append(test_imports())
    results.append(test_prompt_building())
    results.append(test_fallback_no_key())

    if not args.offline:
        if args.single:
            results.append(test_single_alert(args.single))
        else:
            results.append(test_single_alert("port_scan"))
            results.append(test_batch_and_report())

    sep("RESULTS")
    passed = sum(1 for r in results if r)
    print(f"  {passed}/{len(results)} test groups passed")
    if passed < len(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
