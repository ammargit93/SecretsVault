import time
import requests

# Configuration
URL = "http://localhost:8080/secret/read"
TOKEN = "YOUR-TOKEN-FROM-LOGIN"
NUM_REQUESTS = 100

headers = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json"
}
payload = {"secret_key": "Name"}

print(f"🚀 Starting benchmark: {NUM_REQUESTS} requests against {URL}...\n")

latencies = []
success_count = 0

total_start_time = time.perf_counter()
with requests.Session() as session:
    for i in range(NUM_REQUESTS):
        req_start = time.perf_counter()
        try:
            response = session.post(URL, json=payload, headers=headers)
            req_end = time.perf_counter()
            
            if response.status_code == 200:
                success_count += 1
                latencies.append((req_end - req_start) * 1000)
            else:
                print(f"❌ Request {i+1} failed with status code {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print(f"💥 Request {i+1} failed connection: {e}")

total_end_time = time.perf_counter()
total_duration = total_end_time - total_start_time

# Calculate Metrics
if latencies:
    avg_latency = sum(latencies) / len(latencies)
    min_latency = min(latencies)
    max_latency = max(latencies)
    req_per_sec = success_count / total_duration

    print("=" * 40)
    print("📊 BENCHMARK RESULTS")
    print("=" * 40)
    print(f"Total Requests Sent : {NUM_REQUESTS}")
    print(f"Successful Actions  : {success_count} / {NUM_REQUESTS}")
    print(f"Total Execution Time: {total_duration:.4f} seconds")
    print(f"Throughput          : {req_per_sec:.2f} req/sec")
    print("-" * 40)
    print(f"Min Latency         : {min_latency:.2f} ms")
    print(f"Max Latency         : {max_latency:.2f} ms")
    print(f"Avg Latency         : {avg_latency:.2f} ms")
    print("=" * 40)
else:
    print("No requests completed successfully to measure metrics.")