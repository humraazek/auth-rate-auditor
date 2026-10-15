"""
Module 1: Password Entropy & Search Space Analyzer

Calculates mathematical search space (S = R^L), Shannon entropy in bits,
identifies predictable patterns, and calculates theoretical brute-force resistance
time across various hash algorithms and hardware capabilities.
"""

import math
import string
import re

COMMON_PATTERNS = [
    r"^(?:password|admin|root|guest|qwerty|123456|letmein)",
    r"(?:123|abc|qwe|pass)",
]

# Real-world guessing speeds (guesses per second) across hardware tiers
# Values based on Hashcat benchmarks for fast (MD5/NTLM) vs slow (bcrypt/Argon2) hashes
SPEED_PRESETS = {
    "Single CPU Core": {
        "fast_hash": 1.5e7,       # 15 Million/sec (MD5 / SHA-256)
        "slow_hash": 2.0e2,       # 200/sec (bcrypt cost 10 / Argon2)
    },
    "High-End GPU (RTX 4090)": {
        "fast_hash": 1.6e11,      # 160 Billion/sec (MD5 / NTLM)
        "slow_hash": 1.2e5,       # 120,000/sec (bcrypt)
    },
    "Distributed Rig (8x GPU)": {
        "fast_hash": 1.2e12,      # 1.2 Trillion/sec
        "slow_hash": 9.6e5,       # ~1 Million/sec (bcrypt)
    },
}

def analyze_password(password: str) -> dict:
    """
    Performs full cryptographic analysis on a candidate password.
    """
    length = len(password)
    if length == 0:
        return {
            "length": 0,
            "entropy_bits": 0.0,
            "search_space": 0,
            "rating": "Empty",
            "character_sets": {},
            "crack_estimates": {},
            "warnings": ["Password cannot be empty."]
        }

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digits = bool(re.search(r"[0-9]", password))
    has_symbols = bool(re.search(r"[^a-zA-Z0-9]", password))

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digits:
        pool_size += 10
    if has_symbols:
        pool_size += 33

    # Total theoretical permutations: S = pool_size ^ length
    search_space = pool_size ** length

    # Shannon entropy: H = length * log2(pool_size)
    entropy_bits = length * math.log2(pool_size) if pool_size > 0 else 0.0

    # Pattern and weakness detection
    warnings = []
    if length < 8:
        warnings.append("Length is under 8 characters (critical vulnerability).")
    elif length < 12:
        warnings.append("Length is under 12 characters (minimum recommended standard).")

    if not (has_lower and has_upper and has_digits and has_symbols):
        missing = []
        if not has_lower: missing.append("lowercase")
        if not has_upper: missing.append("uppercase")
        if not has_digits: missing.append("digits")
        if not has_symbols: missing.append("special symbols")
        warnings.append(f"Missing character types: {', '.join(missing)}.")

    lower_pw = password.lower()
    for pat in COMMON_PATTERNS:
        if re.search(pat, lower_pw):
            warnings.append("Contains common predictable dictionary prefix or sequence.")
            entropy_bits = max(0.0, entropy_bits - 15.0) # Deduct penalty for known dictionary pattern
            break

    # Determine security rating based on effective entropy bits
    if entropy_bits < 28:
        rating = "Very Weak"
    elif entropy_bits < 45:
        rating = "Weak"
    elif entropy_bits < 65:
        rating = "Moderate"
    elif entropy_bits < 85:
        rating = "Strong"
    else:
        rating = "Very Strong"

    # Compute crack time estimates for each hardware tier
    crack_estimates = {}
    for tier, speeds in SPEED_PRESETS.items():
        fast_sec = search_space / speeds["fast_hash"]
        slow_sec = search_space / speeds["slow_hash"]
        crack_estimates[tier] = {
            "fast_hash_human": format_duration(fast_sec),
            "slow_hash_human": format_duration(slow_sec),
            "fast_seconds": fast_sec,
            "slow_seconds": slow_sec,
        }

    return {
        "length": length,
        "pool_size": pool_size,
        "search_space": search_space,
        "entropy_bits": round(entropy_bits, 2),
        "rating": rating,
        "character_sets": {
            "lowercase": has_lower,
            "uppercase": has_upper,
            "digits": has_digits,
            "symbols": has_symbols,
        },
        "crack_estimates": crack_estimates,
        "warnings": warnings,
    }

def format_duration(seconds: float) -> str:
    """
    Converts raw seconds into readable human time representation.
    """
    if seconds < 0.001:
        return "Instant (< 1 millisecond)"
    if seconds < 1:
        return f"{seconds * 1000:.1f} milliseconds"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"
    days = hours / 24
    if days < 365:
        return f"{days:.1f} days"
    years = days / 365.25
    if years < 1000:
        return f"{years:.1f} years"
    if years < 1_000_000:
        return f"{years / 1000:.1f} thousand years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:.1f} million years"
    return f"{years / 1_000_000_000:.1f} billion years"
