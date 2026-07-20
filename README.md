# SecretsVault

SecretsVault is a highly secure, high-performance secrets management service written in Go using the Fiber web framework. It provides robust protection for sensitive data through **Envelope Encryption** powered by AWS KMS (Key Management Service) and AES-256-GCM, along with in-memory Redis caching and PostgreSQL persistent storage.

---

## Key Features

- **Envelope Encryption**: Multi-layered key encryption workflow:
  - Secrets are encrypted with a dynamic **Data Encryption Key (DEK)** using AES-256-GCM.
  - Each DEK is encrypted with a **Key Encryption Key (KEK)** using AES-256-GCM.
  - Each KEK is encrypted with AWS KMS (or fallback local encryption).
- **Service Registration & Auth**: Services register to receive a unique API Key. Registered services authenticate using their API Key to acquire short-lived JWT tokens.
- **Role-Based Access Control (RBAC)**: Supports roles (`RD`, `WR`, `RDWR`) to restrict endpoints:
  - `RD` (Read-only): Permitted on `/secret/read`, blocked on `/secret/write`.
  - `WR` (Write-only): Permitted on `/secret/write`, blocked on `/secret/read`.
  - `RDWR` (Read-Write): Permitted on all endpoints.
- **Multi-tenant Support**: Supports service-based secret management.
- **In-Memory Redis Caching**: Cache-aside implementation for secret reads to maximize performance and minimize database/KMS requests.
- **Asynchronous Audit Logging**: Logs all read and write actions asynchronously to an `audit.log` file using Go channels, ensuring security compliance without blocking request execution.
- **Continuous Integration (CI/CD)**: Automated GitHub Actions pipeline testing code quality (`go vet`) and integration tests with PostgreSQL and Redis service containers.
- **Performance Benchmarking**: Integrated Python benchmarker to measure latency and throughput.

---

## Envelope Encryption Flow

```
[Plaintext Secret] 
       │
       ▼ (Encrypted with DEK via AES-256-GCM)
[Encrypted Secret] ──> Stored in `secrets` table
       ▲
       │
[Data Encryption Key (DEK)]
       │
       ▼ (Encrypted with KEK via AES-256-GCM)
[Encrypted DEK]    ──> Stored in `dek` table
       ▲
       │
[Key Encryption Key (KEK)]
       │
       ▼ (Encrypted via AWS KMS)
[Encrypted KEK]    ──> Stored in `kek` table
```

---

## Directory Structure

- `.github/workflows/`: GitHub Actions CI/CD workflow configurations.
- `db/`: Database configuration and query wrappers.
- `middleware/`: Web server middlewares including auth, caching, and read/write endpoint handlers.
- `models/`: Go structs defining requests, responses, database schemas, and JWT claims.
- `state/`: Cryptographic utilities for AES-256-GCM and AWS KMS interaction.
- `tests/`: End-to-end integration and unit test suite.
- `utils/`: JWT generation/validation, password hashing, and API Key helper functions.
- `init.sql`: Database schema initialization script.
- `main.go`: Application entrypoint.
- `main.py`: Python client for testing and benchmarking latency/throughput.

---

## Getting Started

### 1. Prerequisites
- **Go** (version 1.20+)
- **PostgreSQL** (version 14+)
- **Redis** (version 6+)
- **Python 3.x** (for testing/benchmarking)
- **AWS Account** with KMS access configured locally (optional)

### 2. Database Setup
Create a PostgreSQL database named `secretsvault` and execute `init.sql` to set up tables and privileges:

```bash
psql -U postgres -d secretsvault -f init.sql
```

Alternatively, manually execute the following SQL schema:

```sql
CREATE TABLE services (
    service_id BIGSERIAL PRIMARY KEY,
    service_name VARCHAR(255) UNIQUE,
    service_api_key VARCHAR(255) UNIQUE NOT NULL,
    service_role VARCHAR(10) NOT NULL
);

CREATE TABLE kek (
    kek_id SERIAL PRIMARY KEY,
    encrypted_kek BYTEA NOT NULL,
    nonce BYTEA NOT NULL
);

CREATE TABLE dek (
    dek_id SERIAL PRIMARY KEY,
    encrypted_dek BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    fk_kek_id INT REFERENCES kek(kek_id) ON DELETE CASCADE
);

CREATE TABLE secrets (
    secret_id BIGSERIAL PRIMARY KEY,
    secret_key VARCHAR(255) UNIQUE NOT NULL,
    fk_dek_id INT REFERENCES dek(dek_id) ON DELETE CASCADE,
    encrypted_secret_value BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    fk_service_id INT REFERENCES services(service_id) ON DELETE CASCADE
);
```

### 3. Environment Configuration
Create a `.env` file in the root directory:
```env
POSTGRES_CONN=postgres://<username>:<password>@localhost:5432/secretsvault?sslmode=disable
REDIS_CONN=localhost:6379
KMS_KEY_ID=arn:aws:kms:YOUR_REGION:YOUR_ACCOUNT_ID:key/YOUR_KEY_ID
USE_KMS=false
```
*Note: Setting `USE_KMS=false` (or leaving it unset) defaults to local envelope encryption with a hardcoded dummy master key. To use AWS KMS, set `USE_KMS=true` and ensure your environment has standard AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) configured.*

### 4. Running the Server
Install dependencies and run the server:
```bash
go mod tidy
go run main.go
```
The server will start listening on port `:8080`.

---

## Testing & CI/CD

### Local Testing
Run the test suite locally:
```bash
go test -v ./tests/...
```

### Continuous Integration (GitHub Actions)
The project includes an automated CI workflow at `.github/workflows/ci.yml`:
- **Triggers**: Executed on every `push` and `pull_request` to `main` or `master`.
- **Services**: Boots PostgreSQL 16 and Redis service containers automatically.
- **Verification**: Applies `init.sql`, executes `go vet ./...`, and runs all integration tests.

---

## API Reference

### 1. Register Service
Registers a new service and generates a hashed API Key.
* **Endpoint**: `POST /register`
* **Request Body**:
```json
{
  "service_name": "analytics_service",
  "service_role": "RDWR"
}
```
* **Response (201 Created)**:
```json
{
  "API_KEY": "sv_ab7b8589..."
}
```

### 2. Service Login
Authenticates the service and retrieves a JWT access token.
* **Endpoint**: `POST /login`
* **Headers**:
  * `SV-API-KEY`: `<YOUR_API_KEY>`
* **Request Body**:
```json
{
  "service_name": "analytics_service",
  "service_role": "RDWR"
}
```
* **Response (200 OK)**:
```json
{
  "token": "eyJhbGciOiJIUzI1Ni..."
}
```

### 3. Write Secret
Encrypts and stores a new secret. Requires `WR` or `RDWR` service role. The `secret_value` can be any JSON-serializable value (e.g., string, number, array, boolean, or nested object).
* **Endpoint**: `POST /secret/write`
* **Headers**:
  * `Authorization`: `Bearer <JWT_TOKEN>`
* **Request Body**:
```json
{
  "secret_key": "db_password",
  "secret_value": "super-secret-password-123"
}
```
* **Response (200 OK)**:
```json
{
  "message": "db_password"
}
```

### 4. Read Secret
Retrieves and decrypts a stored secret. Requires `RD` or `RDWR` service role. Returns the decrypted secret value in its original JSON format.
* **Endpoint**: `POST /secret/read`
* **Headers**:
  * `Authorization`: `Bearer <JWT_TOKEN>`
* **Request Body**:
```json
{
  "secret_key": "db_password"
}
```
* **Response (200 OK)**:
```json
{
  "secret_value": "super-secret-password-123"
}
```

### 5. Update Secret
Updates a stored secret in-place using the existing encryption keys. Requires `WR` or `RDWR` service role.
* **Endpoint**: `POST /secret/update`
* **Headers**:
  * `Authorization`: `Bearer <JWT_TOKEN>`
* **Request Body**:
```json
{
  "secret_key": "db_password",
  "secret_value": "new-super-secret-password-456"
}
```
* **Response (200 OK)**:
```json
{
  "message": "updated",
  "secret_key": "db_password"
}
```

### 6. Delete Secret
Deletes a stored secret and its associated KEK/DEK keys. Requires `WR` or `RDWR` service role.
* **Endpoint**: `POST /secret/delete`
* **Headers**:
  * `Authorization`: `Bearer <JWT_TOKEN>`
* **Request Body**:
```json
{
  "secret_key": "db_password"
}
```
* **Response (200 OK)**:
```json
{
  "message": "deleted",
  "secret_key": "db_password"
}
```

### 7. Health Check
Checks the server health status.
* **Endpoint**: `GET /health`
* **Response (200 OK)**:
```text
OK
```

---

## Audit Logging

The service includes an asynchronous audit logging system using Go channels. When a secret is read or written, an access event is logged in a separate goroutine to prevent request-handling latency.

Logs are appended to `audit.log` in the following space-delimited format:
```
<timestamp> <secret_key> <service_name> <service_role> <operation>
```

### Log Fields:
- **Timestamp**: The date and time of the event (e.g., `2026-06-09 19:04:16`).
- **Secret Key**: The key of the secret being accessed or written (e.g., `Email`).
- **Service Name**: The name of the service performing the operation (e.g., `auth`).
- **Service Role**: The role of the service at the time of the operation (e.g., `RDWR`).
- **Operation**: The type of operation (`RD` for Read, `WR` for Write, `UP` for Update, `DL` for Delete).

Example entry:
```text
2026-06-09 19:04:16 Email auth RDWR WR
```

---

## Benchmarking & Testing
A Python script (`main.py`) is provided to benchmark the read throughput and latency of the server:
1. Ensure the Python environment has the `requests` library installed:
   ```bash
   pip install requests
   ```
2. Configure the JWT token inside `main.py` if needed.
3. Start the Go server.
4. Run the benchmark:
   ```bash
   python main.py
   ```
This will send multiple sequential requests and output a detailed metrics report including min/max/average latency and throughput (requests/second).
