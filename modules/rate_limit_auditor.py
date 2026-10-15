"""
Module 2: Defensive Rate-Limit & Lockout Auditor

Sends a strictly controlled sequence of benign test requests against a user-specified
endpoint to measure and verify defensive thresholds (rate limiting, account lockouts,
exponential backoff, and timing-safe responses).
"""

import time
import urllib.request
import urllib.error
import urllib.parse
import statistics

def audit_endpoint(url: str, attempts: int = 10, username: str = "audit_probe_user", delay_between: float = 0.1) -> dict:
    """
    Evaluates server-side defenses against repetitive authentication attempts.
    """
    if attempts < 3:
        attempts = 3
    if attempts > 30:
        attempts = 30  # Safety cap to avoid DoS on target

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    results = []
    headers = {
        "User-Agent": "AuthResilienceAuditor/1.0 (Defensive Compliance Scanner; +https://github.com/humraazek/Brute-force-simulator)",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    print(f"[*] Starting defensive audit against: {url}")
    print(f"[*] Sending {attempts} controlled test probes...")

    status_codes = []
    response_times = []
    retry_after_observed = False
    lockout_observed = False
    rate_limited = False

    for i in range(1, attempts + 1):
        # Benign dummy payload
        data = urllib.parse.urlencode({
            "username": username,
            "password": f"ProbePass_{i}_!@"
        }).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        start_t = time.perf_counter()
        status = 0
        response_header_retry = None

        try:
            with urllib.request.urlopen(req, timeout=8.0) as resp:
                elapsed = time.perf_counter() - start_t
                status = resp.status
                response_header_retry = resp.headers.get("Retry-After")
        except urllib.error.HTTPError as err:
            elapsed = time.perf_counter() - start_t
            status = err.code
            response_header_retry = err.headers.get("Retry-After") if err.headers else None
        except Exception as e:
            elapsed = time.perf_counter() - start_t
            status = -1  # Connection error / timeout

        status_codes.append(status)
        response_times.append(elapsed)

        if status == 429:
            rate_limited = True
        elif status == 423:
            lockout_observed = True
        if response_header_retry:
            retry_after_observed = True

        results.append({
            "attempt": i,
            "status": status,
            "latency_ms": round(elapsed * 1000, 2),
            "retry_after": response_header_retry,
        })

        if delay_between > 0 and i < attempts:
            time.sleep(delay_between)

    # Statistical timing analysis
    avg_latency = statistics.mean(response_times) if response_times else 0
    stdev_latency = statistics.stdev(response_times) if len(response_times) > 1 else 0

    # Progressive delay check: does latency continuously increase across consecutive attempts?
    increasing_delays = True
    for idx in range(1, len(response_times)):
        if response_times[idx] < response_times[idx - 1] * 1.1:
            increasing_delays = False
            break

    # Compliance Scorecard
    scorecard = {
        "rate_limiting_enforced": rate_limited,
        "account_lockout_detected": lockout_observed,
        "retry_after_header_present": retry_after_observed,
        "progressive_backoff_detected": increasing_delays and (response_times[-1] > response_times[0] * 2.0),
        "timing_jitter_ms": round(stdev_latency * 1000, 2),
        "average_latency_ms": round(avg_latency * 1000, 2),
    }

    # Recommendations
    recommendations = []
    if not rate_limited and not lockout_observed:
        recommendations.append("HIGH: No rate limiting (HTTP 429) or lockout observed after multiple consecutive failures.")
    if not scorecard["progressive_backoff_detected"]:
        recommendations.append("MEDIUM: Implement progressive delays (exponential backoff) on repeated authentication failures.")
    if rate_limited and not retry_after_observed:
        recommendations.append("LOW: Provide a 'Retry-After' header when returning HTTP 429 to inform clients of cooldown periods.")

    return {
        "target": url,
        "total_probes": attempts,
        "probes": results,
        "scorecard": scorecard,
        "recommendations": recommendations,
    }
