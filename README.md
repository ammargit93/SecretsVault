# SecretsVault

SecretsVault is a highly secure, high-performance secrets management service written in Go using the Fiber web framework. It provides robust protection for sensitive data through **Envelope Encryption** powered by AWS KMS (Key Management Service) and AES-256-GCM.

---

## Key Features

- **Envelope Encryption**: Multi-layered key encryption workflow:
  - Secrets are encrypted with a dynamic **Data Encryption Key (DEK)** using AES-256-GCM.
  - Each DEK is encrypted with a **Key Encryption Key (KEK)** using AES-256-GCM.
  - Each KEK is encrypted with AWS KMS.
- **Service Registration & Auth**: Services register to receive a unique API Key. Registered services authenticate using their API Key to acquire short-lived JWT tokens.
- **Role-Based Access Control (RBAC)**: Supports roles (`RD`, `WR`, `RDWR`) to restrict endpoints:
  - `RD` (Read-only): Permitted on `/secret/read`, blocked on `/secret/write`.
  - `WR` (Write-only): Permitted on `/secret/write`, blocked on `/secret/read`.
  - `RDWR` (Read-Write): Permitted on all endpoints.
- **In-Memory Caching**: Cache-aside implementation for secret reads to maximize performance and minimize database/KMS requests.
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

- `db/`: Database configuration and query wrappers.
- `middleware/`: Web server middlewares including auth, caching, and read/write endpoint handlers.
- `models/`: Go structs defining requests, responses, database schemas, and JWT claims.
- `state/`: Cryptographic utilities for AES-256-GCM and AWS KMS interaction.
- `utils/`: JWT generation/validation, password hashing, and API Key helper functions.
- `main.go`: Application entrypoint.
- `main.py`: Python client for testing and benchmarking latency/throughput.

---

## Getting Started

### 1. Prerequisites
- **Go** (version 1.20+)
- **PostgreSQL**
- **Python 3.x** (for testing/benchmarking)
- **AWS Account** with KMS access configured locally (e.g., via AWS CLI or env variables)

### 2. Database Setup
Create a PostgreSQL database named `secretsvault` and execute the following SQL schema to create the required tables:

```sql
CREATE TABLE services (
    service_name VARCHAR(255) PRIMARY KEY,
    service_api_key VARCHAR(255) NOT NULL,
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
    secret_key VARCHAR(255) PRIMARY KEY,
    fk_dek_id INT REFERENCES dek(dek_id) ON DELETE CASCADE,
    encrypted_secret_value BYTEA NOT NULL,
    nonce BYTEA NOT NULL
);
```

### 3. Environment Configuration
Create a `.env` file in the root directory:
```env
PORT=8080
KMS_KEY_ID=arn:aws:kms:YOUR_REGION:YOUR_ACCOUNT_ID:key/YOUR_KEY_ID
AWS_REGION=ap-south-1
```
*Note: Ensure your environment has standard AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) exported or configured via AWS credentials profile.*

### 4. Running the Server
Install dependencies and run the server:
```bash
go mod tidy
go run main.go
```
The server will start listening on port `:8080`.

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
Encrypts and stores a new secret. Requires `WR` or `RDWR` service role.
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
Retrieves and decrypts a stored secret. Requires `RD` or `RDWR` service role.
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
