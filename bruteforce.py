#!/usr/bin/env python3
"""
Backwards Compatibility Shim

The original script has been refactored into the modular
Authentication Security & Resilience Simulator suite.

Please use simulator.py directly:
    python simulator.py --help
"""

import sys
from simulator import main

if __name__ == "__main__":
    print("[*] Notice: bruteforce.py has been modernized into the unified Simulator suite.")
    print("[*] Launching simulator.py...\n")
    main()
