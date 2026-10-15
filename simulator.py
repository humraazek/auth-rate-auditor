#!/usr/bin/env python3
"""
Authentication Security & Resilience Simulator

A unified security framework providing:
1. Password entropy, search-space, and crack-time feasibility analysis
2. Defensive rate-limiting & lockout compliance auditor for web endpoints
3. Interactive local defense simulation lab (Token Bucket, Lockout, Progressive Backoff)
"""

import sys
import argparse
import json

from modules.entropy_analyzer import analyze_password
from modules.rate_limit_auditor import audit_endpoint
from modules.mock_auth_lab import run_lab_simulation


def print_banner():
    banner = r"""
 =========================================================================
   AUTHENTICATION SECURITY & RESILIENCE SIMULATOR (v2.0)
   Defensive Analysis | Rate-Limit Auditing | Interactive Lab
 =========================================================================
"""
    print(banner)


def handle_analyze(args):
    password = args.password
    if not password:
        import getpass
        password = getpass.getpass("Enter password to analyze: ")

    results = analyze_password(password)

    print("=" * 65)
    print(" PASSWORD ENTROPY & SEARCH-SPACE ANALYSIS")
    print("=" * 65)
    print(f"Password Length    : {results['length']} characters")
    print(f"Character Pool (R) : {results['pool_size']} possible symbols")
    print(f"Search Space (R^L) : {results['search_space']:.2e} combinations")
    print(f"Shannon Entropy    : {results['entropy_bits']} bits")
    print(f"Security Rating    : [{results['rating'].upper()}]")
    print("-" * 65)

    print("Character Classes Detected:")
    for cset, present in results["character_sets"].items():
        symbol = "[+]" if present else "[-]"
        print(f"  {symbol} {cset.capitalize()}")

    if results["warnings"]:
        print("\nIdentified Weaknesses & Policy Warnings:")
        for w in results["warnings"]:
            print(f"  [!] {w}")

    print("\n" + "=" * 65)
    print(" THEORETICAL BRUTE-FORCE RESISTANCE BY HARDWARE TIER")
    print("=" * 65)
    print(f"{'Hardware Tier':<26} | {'Fast Hash (MD5)':<18} | {'Slow Hash (bcrypt)'}")
    print("-" * 65)
    for tier, data in results["crack_estimates"].items():
        print(f"{tier:<26} | {data['fast_hash_human']:<18} | {data['slow_hash_human']}")
    print("=" * 65 + "\n")


def handle_audit(args):
    url = args.url
    attempts = args.attempts
    delay = args.delay

    print("=" * 65)
    print(" DEFENSIVE RATE-LIMIT & LOCKOUT AUDITOR")
    print("=" * 65)
    print(f"Target URL   : {url}")
    print(f"Probe Count  : {attempts}")
    print(f"Inter-delay  : {delay}s")
    print("=" * 65 + "\n")

    try:
        report = audit_endpoint(url, attempts=attempts, delay_between=delay)
    except Exception as e:
        print(f"[!] Audit failed: {e}")
        sys.exit(1)

    print("\n" + "=" * 65)
    print(" AUDIT COMPLIANCE SCORECARD")
    print("=" * 65)
    scorecard = report["scorecard"]
    print(f"Rate Limiting Enforced (429)     : {'YES [PASS]' if scorecard['rate_limiting_enforced'] else 'NO  [FAIL]'}")
    print(f"Account Lockout Detected (423)   : {'YES [PASS]' if scorecard['account_lockout_detected'] else 'NO  [NOT DETECTED]'}")
    print(f"Progressive Backoff Detected     : {'YES [PASS]' if scorecard['progressive_backoff_detected'] else 'NO  [NOT DETECTED]'}")
    print(f"Retry-After Header Returned      : {'YES [PASS]' if scorecard['retry_after_header_present'] else 'NO  [NOT DETECTED]'}")
    print(f"Average Server Latency           : {scorecard['average_latency_ms']} ms")
    print(f"Timing Variance (Jitter)         : {scorecard['timing_jitter_ms']} ms")
    print("-" * 65)

    if report["recommendations"]:
        print("Defensive Hardening Recommendations:")
        for rec in report["recommendations"]:
            print(f"  * {rec}")
    else:
        print("All standard authentication rate-limiting defenses appear active!")
    print("=" * 65 + "\n")


def handle_lab(args):
    if args.benchmark:
        print("=" * 70)
        print(" RUNNING COMPARATIVE DEFENSE BENCHMARK (ALL 4 MODES)")
        print("=" * 70 + "\n")
        modes = ["none", "progressive-delay", "lockout", "token-bucket"]
        summaries = []

        for m in modes:
            res = run_lab_simulation(defense_mode=m, num_probes=args.probes, port=8999)
            summaries.append(res)
            print()

        print("=" * 75)
        print(" EXECUTIVE BENCHMARK COMPARISON TABLE")
        print("=" * 75)
        print(f"{'Defense Strategy':<20} | {'Probes':<8} | {'Blocked':<8} | {'Total Time':<12} | {'Mitigation Status'}")
        print("-" * 75)
        for s in summaries:
            mode = s["defense_mode"].capitalize()
            blocked = s["blocked"]
            dur = f"{s['duration_seconds']:.2f}s"
            status = "100% Vulnerable" if blocked == 0 and "progressive" not in s["defense_mode"] else (
                "Slowing Automation" if "progressive" in s["defense_mode"] else f"Blocked {blocked} attempts"
            )
            print(f"{mode:<20} | {s['total_probes']:<8} | {blocked:<8} | {dur:<12} | {status}")
        print("=" * 75 + "\n")

    else:
        run_lab_simulation(defense_mode=args.defense, num_probes=args.probes, port=args.port)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Authentication Security & Resilience Simulator - Analyze, Audit, and Simulate Authentication Defenses."
    )
    subparsers = parser.add_subparsers(dest="command", help="Operational mode")

    # Mode 1: Analyze
    parser_analyze = subparsers.add_parser("analyze", help="Calculate password entropy and theoretical crack times")
    parser_analyze.add_argument("-p", "--password", help="Password string to analyze (or prompted securely if omitted)")

    # Mode 2: Audit
    parser_audit = subparsers.add_parser("audit", help="Audit defensive rate limiting on a target web endpoint")
    parser_audit.add_argument("--url", required=True, help="Target authentication URL (e.g. http://127.0.0.1:8000/login)")
    parser_audit.add_argument("--attempts", type=int, default=10, help="Number of benign test attempts (default: 10, max: 30)")
    parser_audit.add_argument("--delay", type=float, default=0.1, help="Delay between probes in seconds (default: 0.1)")

    # Mode 3: Lab
    parser_lab = subparsers.add_parser("lab", help="Run local interactive authentication defense simulation lab")
    parser_lab.add_argument(
        "--defense",
        choices=["token-bucket", "lockout", "progressive-delay", "none"],
        default="token-bucket",
        help="Defense mechanism to activate on the mock server"
    )
    parser_lab.add_argument("--probes", type=int, default=10, help="Number of simulated requests to send (default: 10)")
    parser_lab.add_argument("--port", type=int, default=8999, help="Local mock server port (default: 8999)")
    parser_lab.add_argument("--benchmark", action="store_true", help="Benchmark all 4 defense modes side-by-side")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "analyze":
        handle_analyze(args)
    elif args.command == "audit":
        handle_audit(args)
    elif args.command == "lab":
        handle_lab(args)


if __name__ == "__main__":
    main()
