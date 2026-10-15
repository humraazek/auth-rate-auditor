"""
Module 3: Interactive Authentication Defense Lab

Spins up a lightweight local mock server with toggleable defense algorithms
(Token Bucket, Account Lockout, Progressive Backoff, or No Defense)
and runs an educational client simulation to demonstrate how defenses work.
"""

import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import json

class MockAuthServerState:
    def __init__(self, defense_mode="token-bucket"):
        self.defense_mode = defense_mode
        self.lock = threading.Lock()
        
        # Lockout state: { username: { "attempts": count, "locked_until": timestamp } }
        self.lockouts = {}
        
        # Token bucket state: { ip: { "tokens": float, "last_refill": timestamp } }
        self.token_buckets = {}
        self.bucket_capacity = 5.0
        self.refill_rate = 0.5  # 0.5 tokens per second (1 token every 2s)

        # Progressive backoff state: { ip: consecutive_failure_count }
        self.failure_counts = {}

    def handle_login(self, client_ip: str, username: str, password: str) -> tuple[int, dict, float]:
        """
        Returns (http_status, response_body, artificial_delay_applied)
        """
        with self.lock:
            now = time.time()
            delay = 0.0

            # ----------------------------------------------------
            # Defense 1: Token Bucket Rate Limiter
            # ----------------------------------------------------
            if self.defense_mode == "token-bucket":
                bucket = self.token_buckets.get(client_ip, {"tokens": self.bucket_capacity, "last_refill": now})
                elapsed = now - bucket["last_refill"]
                bucket["tokens"] = min(self.bucket_capacity, bucket["tokens"] + (elapsed * self.refill_rate))
                bucket["last_refill"] = now

                if bucket["tokens"] < 1.0:
                    self.token_buckets[client_ip] = bucket
                    return 429, {"error": "Too Many Requests", "reason": "Token bucket exhausted", "retry_after": 2}, 0.0
                
                bucket["tokens"] -= 1.0
                self.token_buckets[client_ip] = bucket

            # ----------------------------------------------------
            # Defense 2: Account Lockout Threshold
            # ----------------------------------------------------
            elif self.defense_mode == "lockout":
                record = self.lockouts.get(username, {"attempts": 0, "locked_until": 0})
                if record["locked_until"] > now:
                    remaining = int(record["locked_until"] - now)
                    return 423, {"error": "Account Locked", "retry_after": remaining}, 0.0

            # ----------------------------------------------------
            # Defense 3: Progressive Delay / Exponential Backoff
            # ----------------------------------------------------
            elif self.defense_mode == "progressive-delay":
                fails = self.failure_counts.get(client_ip, 0)
                if fails > 0:
                    # Exponential delay: 0.1s, 0.2s, 0.4s, 0.8s, 1.6s... capped at 3s
                    delay = min(3.0, 0.1 * (2 ** (fails - 1)))

            # Mock credential verification
            # Valid test credential is "admin" / "CorrectHorseBatteryStaple!"
            is_valid = (username == "admin" and password == "CorrectHorseBatteryStaple!")

            if is_valid:
                # Reset counters on success
                self.lockouts.pop(username, None)
                self.failure_counts.pop(client_ip, None)
                return 200, {"status": "Authenticated", "user": username}, delay

            # Handle failed authentication counters
            if self.defense_mode == "lockout":
                record = self.lockouts.get(username, {"attempts": 0, "locked_until": 0})
                record["attempts"] += 1
                if record["attempts"] >= 5:
                    record["locked_until"] = now + 60.0  # Lock for 60 seconds
                    record["attempts"] = 0
                self.lockouts[username] = record

            elif self.defense_mode == "progressive-delay":
                self.failure_counts[client_ip] = self.failure_counts.get(client_ip, 0) + 1

            return 401, {"error": "Invalid credentials"}, delay


def make_request_handler(state: MockAuthServerState):
    class LabHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # Silence default HTTP server console logs for clean CLI output

        def do_POST(self):
            if self.path != "/login":
                self.send_response(404)
                self.end_headers()
                return

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            params = urllib.parse.parse_qs(body)

            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            client_ip = self.client_address[0]

            status, resp_data, delay = state.handle_login(client_ip, username, password)

            if delay > 0:
                time.sleep(delay)

            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            if "retry_after" in resp_data:
                self.send_header("Retry-After", str(resp_data["retry_after"]))
            self.end_headers()
            self.wfile.write(json.dumps(resp_data).encode("utf-8"))

    return LabHandler


def run_lab_simulation(defense_mode: str = "token-bucket", num_probes: int = 10, port: int = 8999):
    """
    Spins up the mock server on localhost, runs simulated probes, and prints comparative results.
    """
    state = MockAuthServerState(defense_mode=defense_mode)
    handler = make_request_handler(state)
    server = HTTPServer(("127.0.0.1", port), handler)

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    time.sleep(0.2)  # Wait for server to bind

    print("=" * 70)
    print(f"LAB SIMULATION: Defense Mode = [{defense_mode.upper()}]")
    print(f"Server listening locally at http://127.0.0.1:{port}/login")
    print("=" * 70)

    url = f"http://127.0.0.1:{port}/login"
    probes_summary = []
    total_start = time.perf_counter()

    print(f"{'Attempt':<8} | {'Status Code':<12} | {'Latency':<12} | {'Server Response / Defense Action'}")
    print("-" * 70)

    import urllib.request
    import urllib.error

    for i in range(1, num_probes + 1):
        data = urllib.parse.urlencode({"username": "admin", "password": f"wrong_pass_{i}"}).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")

        t0 = time.perf_counter()
        status = 0
        message = ""

        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                elapsed = time.perf_counter() - t0
                status = resp.status
                message = "200 OK (Unexpected success)"
        except urllib.error.HTTPError as err:
            elapsed = time.perf_counter() - t0
            status = err.code
            if status == 401:
                message = "401 Unauthorized (Normal failure)"
            elif status == 429:
                message = "429 Too Many Requests (Rate limit triggered!)"
            elif status == 423:
                message = "423 Locked (Account lockout active!)"
            else:
                message = f"{status} Error"
        except Exception as e:
            elapsed = time.perf_counter() - t0
            status = -1
            message = f"Error: {e}"

        latency_str = f"{elapsed * 1000:.1f} ms"
        print(f"#{i:<7} | {status:<12} | {latency_str:<12} | {message}")

        probes_summary.append({
            "attempt": i,
            "status": status,
            "elapsed": elapsed
        })
        time.sleep(0.05)

    total_duration = time.perf_counter() - total_start
    server.shutdown()

    # Summary statistics
    blocked = sum(1 for p in probes_summary if p["status"] in (429, 423))
    print("-" * 70)
    print(f"SIMULATION FINISHED in {total_duration:.2f} seconds.")
    print(f"Total Probes: {num_probes} | Blocked/Throttled: {blocked} | Pass Rate: {((num_probes - blocked) / num_probes) * 100:.1f}%\n")

    return {
        "defense_mode": defense_mode,
        "total_probes": num_probes,
        "blocked": blocked,
        "duration_seconds": total_duration
    }
