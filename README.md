# Authentication Security & Resilience Simulator

A unified Python security toolkit for analyzing password entropy, auditing web authentication rate limits, and simulating defensive mitigation mechanisms (Token Bucket, Account Lockout, and Progressive Backoff).

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/humraazek/Brute-force-simulator.git
cd Brute-force-simulator

# 2. Run unit tests
python -m unittest discover -s tests

# 3. Analyze a password's entropy and theoretical crack time
python simulator.py analyze -p "MySecretPassword123!"

# 4. Run an interactive defense benchmark in the local lab
python simulator.py lab --benchmark
```

---

## Features

### 1. Password Entropy & Search Space Analyzer (`analyze`)
- **Mathematical Space Computation**: Calculates total search space ($S = R^L$) and Shannon entropy in bits ($H = L \cdot \log_2(R)$).
- **Pattern & Weakness Flagging**: Detects predictable sequences, common dictionary words, and character set deficiencies.
- **Hardware Tier Crack Estimation**: Estimates theoretical brute-force resistance across fast hashes (MD5, NTLM) vs. slow memory-hard hashes (bcrypt, Argon2) on single CPUs, modern GPUs (RTX 4090), and distributed rigs.

### 2. Defensive Rate-Limit & Lockout Auditor (`audit`)
- **Compliance Scorecard**: Sends a controlled sequence of benign probe requests to verify if an endpoint triggers HTTP `429 Too Many Requests`, account lockout (`423 Locked`), or returns a `Retry-After` header.
- **Progressive Backoff Verification**: Measures latency progressions across consecutive attempts to identify exponential backoff defense.
- **Timing Variance Measurement**: Evaluates latency standard deviation to assess vulnerability to timing attacks.

### 3. Interactive Defense Simulation Lab (`lab`)
- **Local Mock Server**: Spins up a local test authentication server on `127.0.0.1` implementing real-world defense algorithms without external dependencies.
- **Configurable Defense Strategies**:
  - `none`: Baseline vulnerable authentication server.
  - `token-bucket`: Token bucket rate limiter with configurable capacity and refill rate.
  - `lockout`: Account lockout triggering after $N$ failed attempts.
  - `progressive-delay`: Exponential latency penalty per consecutive failure.
- **Side-by-Side Benchmark (`--benchmark`)**: Runs all four defenses in sequence and prints an executive summary table detailing total time taken, requests blocked, and mitigation efficiency.

---

## Usage Guide

### Command 1: Analyze Password Strength & Search Space

```bash
# Direct analysis
python simulator.py analyze -p "SuperSecret123!@#"

# Interactive prompt (hides password input)
python simulator.py analyze
```

**Sample Output:**
```
=================================================================
 PASSWORD ENTROPY & SEARCH-SPACE ANALYSIS
=================================================================
Password Length    : 17 characters
Character Pool (R) : 95 possible symbols
Search Space (R^L) : 4.18e+33 combinations
Shannon Entropy    : 96.69 bits
Security Rating    : [VERY STRONG]
-----------------------------------------------------------------
Character Classes Detected:
  [+] Lowercase
  [+] Uppercase
  [+] Digits
  [+] Symbols

=================================================================
 THEORETICAL BRUTE-FORCE RESISTANCE BY HARDWARE TIER
=================================================================
Hardware Tier              | Fast Hash (MD5)    | Slow Hash (bcrypt)
-----------------------------------------------------------------
Single CPU Core            | 8.8 billion years  | > 100 billion years
High-End GPU (RTX 4090)    | 828,000 years      | > 100 billion years
Distributed Rig (8x GPU)   | 110,000 years      | > 100 billion years
=================================================================
```

---

### Command 2: Audit Web Authentication Endpoint

Test your own development server for rate-limiting compliance:

```bash
python simulator.py audit --url "http://127.0.0.1:8000/login" --attempts 10 --delay 0.1
```

**Scorecard Output:**
```
=================================================================
 AUDIT COMPLIANCE SCORECARD
=================================================================
Rate Limiting Enforced (429)     : YES [PASS]
Account Lockout Detected (423)   : YES [PASS]
Progressive Backoff Detected     : NO  [NOT DETECTED]
Retry-After Header Returned      : YES [PASS]
Average Server Latency           : 18.2 ms
Timing Variance (Jitter)         : 2.1 ms
-----------------------------------------------------------------
Defensive Hardening Recommendations:
  * MEDIUM: Implement progressive delays (exponential backoff) on repeated authentication failures.
=================================================================
```

---

### Command 3: Run Interactive Defense Lab

#### Test a Single Defense Strategy
```bash
# Test Token Bucket rate limiter (returns HTTP 429 after 5 attempts)
python simulator.py lab --defense token-bucket --probes 8

# Test Account Lockout (locks after 5 failed attempts)
python simulator.py lab --defense lockout --probes 8

# Test Progressive Backoff (exponential delay added to each failure)
python simulator.py lab --defense progressive-delay --probes 6
```

#### Run All 4 Defenses in a Benchmark Comparison
```bash
python simulator.py lab --benchmark --probes 6
```

**Benchmark Summary Table:**
```
===========================================================================
 EXECUTIVE BENCHMARK COMPARISON TABLE
===========================================================================
Defense Strategy     | Probes   | Blocked  | Total Time   | Mitigation Status
---------------------------------------------------------------------------
None                 | 6        | 0        | 0.41s        | 100% Vulnerable
Progressive-delay    | 6        | 0        | 3.49s        | Slowing Automation
Lockout              | 6        | 1        | 0.37s        | Blocked 1 attempts
Token-bucket         | 6        | 1        | 0.43s        | Blocked 1 attempts
===========================================================================
```

---

## Automated Tests

Run the built-in test suite:

```bash
python -m unittest discover -s tests
```

---

## Project Structure

```
Brute-force-simulator/
├── simulator.py                # Main CLI entry point
├── bruteforce.py               # Backwards compatibility launcher
├── modules/
│   ├── __init__.py
│   ├── entropy_analyzer.py     # Password search-space and entropy calculator
│   ├── rate_limit_auditor.py   # Rate limiting and lockout compliance auditor
│   └── mock_auth_lab.py        # Mock server with Token Bucket, Lockout, Backoff
├── tests/
│   ├── __init__.py
│   └── test_simulator.py       # Automated unit test suite
├── requirements.txt            # Dependency documentation (zero external deps)
└── README.md                   # Documentation
```

---

## Defensive Recommendations (OWASP Authentication Cheat Sheet)

1. **Enforce Rate Limiting**: Limit failed authentication attempts per IP and per username using algorithms like Token Bucket or Leaky Bucket. Return HTTP `429 Too Many Requests` with a `Retry-After` header.
2. **Implement Progressive Delays**: Apply exponential backoff (e.g., $100\text{ ms} \times 2^{\text{attempts}-1}$) to increase the cost of automation.
3. **Use Adaptive Lockouts**: Implement temporary, progressive account lockouts (e.g., 5-minute lockout after 5 consecutive failures) to prevent automated dictionary attacks.
4. **Mandate Strong Password Entropy**: Reject passwords with fewer than 12 characters, predictable patterns, or low Shannon entropy.
5. **Adopt Modern Password Hashing**: Store passwords using memory-hard, computationally expensive algorithms such as **Argon2id** or **bcrypt** with adequate work factors.

---

## License

Licensed under the [MIT License](LICENSE).
