import time
import statistics
import requests
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==========================================================
# Configuration
# ==========================================================

BASE_URL = "http://localhost:8080"

WRITE_URL = f"{BASE_URL}/secret/write"
READ_URL = f"{BASE_URL}/secret/read"

TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXJ2aWNlX25hbWUiOiJhdXRoX3Rlc3RfMTc4Mzk0OTIzMCIsInNlcnZpY2Vfcm9sZSI6IlJEV1IiLCJleHAiOjE3ODM5NTI4MzksImlhdCI6MTc4Mzk0OTIzOX0.KlBEaMo1z3lb7hUbsJGH88Ev5ZbQZ2XeNwv9byOjtSg"
NUM_SECRETS = 100
NUM_WORKERS = 50

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
}

# ==========================================================
# Helpers
# ==========================================================

def percentile(data, pct):
    if not data:
        return 0.0

    sorted_data = sorted(data)
    idx = int(len(sorted_data) * pct / 100)

    if idx >= len(sorted_data):
        idx = len(sorted_data) - 1

    return sorted_data[idx]


# ==========================================================
# API Calls
# ==========================================================

def write_secret(session, key, value):
    payload = {
        "secret_key": key,
        "secret_value": value
    }

    start = time.perf_counter()

    try:
        response = session.post(
            WRITE_URL,
            json=payload,
            headers=HEADERS,
            timeout=10
        )

        latency_ms = (time.perf_counter() - start) * 1000

        return response.status_code == 200, latency_ms

    except Exception:
        latency_ms = (time.perf_counter() - start) * 1000
        return False, latency_ms


def read_secret(session, key):
    payload = {
        "secret_key": key
    }

    start = time.perf_counter()

    try:
        response = session.post(
            READ_URL,
            json=payload,
            headers=HEADERS,
            timeout=10
        )

        latency_ms = (time.perf_counter() - start) * 1000

        return response.status_code == 200, latency_ms

    except Exception:
        latency_ms = (time.perf_counter() - start) * 1000
        return False, latency_ms


# ==========================================================
# Benchmark Runner
# ==========================================================

def run_benchmark(session, keys, mode="read"):
    latencies = []

    success_count = 0
    failure_count = 0

    benchmark_start = time.perf_counter()

    with ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:

        if mode == "write":
            futures = {
                executor.submit(
                    write_secret,
                    session,
                    key,
                    f"value_{key.split('_')[1]}"
                ): key
                for key in keys
            }

        else:
            futures = {
                executor.submit(
                    read_secret,
                    session,
                    key
                ): key
                for key in keys
            }

        for future in as_completed(futures):

            try:
                success, latency = future.result()

                if success:
                    success_count += 1
                else:
                    failure_count += 1

                latencies.append(latency)

            except Exception:
                failure_count += 1

    benchmark_end = time.perf_counter()

    total_time = benchmark_end - benchmark_start

    total_requests = success_count + failure_count

    throughput = (
        total_requests / total_time
        if total_time > 0
        else 0
    )

    error_rate = (
        failure_count / total_requests * 100
        if total_requests > 0
        else 0
    )

    return {
        "requests": total_requests,
        "success": success_count,
        "failure": failure_count,
        "error_rate": error_rate,
        "total_time": total_time,
        "throughput": throughput,
        "min_latency": min(latencies) if latencies else 0,
        "max_latency": max(latencies) if latencies else 0,
        "avg_latency": statistics.mean(latencies) if latencies else 0,
        "p50_latency": percentile(latencies, 50),
        "p95_latency": percentile(latencies, 95),
        "p99_latency": percentile(latencies, 99),
    }


# ==========================================================
# Pretty Printer
# ==========================================================

def print_results(title, result):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)

    print(f"Requests       : {result['requests']}")
    print(f"Success        : {result['success']}")
    print(f"Failures       : {result['failure']}")
    print(f"Error Rate     : {result['error_rate']:.2f}%")

    print("-" * 60)

    print(f"Total Time     : {result['total_time']:.4f} sec")
    print(f"Throughput     : {result['throughput']:.2f} req/sec")

    print("-" * 60)

    print(f"Min Latency    : {result['min_latency']:.2f} ms")
    print(f"Max Latency    : {result['max_latency']:.2f} ms")
    print(f"Average        : {result['avg_latency']:.2f} ms")
    print(f"P50 Latency    : {result['p50_latency']:.2f} ms")
    print(f"P95 Latency    : {result['p95_latency']:.2f} ms")
    print(f"P99 Latency    : {result['p99_latency']:.2f} ms")


# ==========================================================
# Main
# ==========================================================

def main():
    print("🚀 SecretsVault Load Benchmark")
    print(f"Secrets       : {NUM_SECRETS}")
    print(f"Workers       : {NUM_WORKERS}")

    session = requests.Session()

    adapter = HTTPAdapter(
        pool_connections=NUM_WORKERS,
        pool_maxsize=NUM_WORKERS
    )

    session.mount("http://", adapter)
    session.mount("https://", adapter)

    keys = [f"secret_{i}" for i in range(NUM_SECRETS)]

    # ------------------------------------------------------
    # Write Phase
    # ------------------------------------------------------

    print("\n✍️ Writing secrets...")
    write_result = run_benchmark(
        session,
        keys,
        mode="write"
    )

    print_results("WRITE BENCHMARK", write_result)

    # ------------------------------------------------------
    # Warmup
    # ------------------------------------------------------

    print("\n🔥 Warming cache...")
    _ = run_benchmark(
        session,
        keys,
        mode="read"
    )

    # ------------------------------------------------------
    # Actual Read Benchmark
    # ------------------------------------------------------

    print("\n📖 Running read benchmark...")
    read_result = run_benchmark(
        session,
        keys,
        mode="read"
    )

    print_results("READ BENCHMARK", read_result)

    # ------------------------------------------------------
    # Resume-Friendly Summary
    # ------------------------------------------------------

    print("\n" + "=" * 60)
    print("RESUME / INTERVIEW METRICS")
    print("=" * 60)

    print(
        f"Sustained {read_result['throughput']:.0f} req/sec "
        f"with {NUM_WORKERS} concurrent clients."
    )

    print(
        f"P95 latency: {read_result['p95_latency']:.2f} ms"
    )

    print(
        f"P99 latency: {read_result['p99_latency']:.2f} ms"
    )

    print(
        f"Error rate: {read_result['error_rate']:.2f}%"
    )


if __name__ == "__main__":
    main()