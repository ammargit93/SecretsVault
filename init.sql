-- PostgreSQL schema initialization for SecretsVault

SELECT 'CREATE DATABASE secretsvault'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'secretsvault')\gexec

\c secretsvault

CREATE TABLE IF NOT EXISTS services (
    service_id BIGSERIAL PRIMARY KEY,
    service_name VARCHAR(255) UNIQUE,
    service_api_key VARCHAR(255) UNIQUE NOT NULL,
    service_role VARCHAR(10) NOT NULL
);

CREATE TABLE IF NOT EXISTS kek (
    kek_id SERIAL PRIMARY KEY,
    encrypted_kek BYTEA NOT NULL,
    nonce BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS dek (
    dek_id SERIAL PRIMARY KEY,
    encrypted_dek BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    fk_kek_id INT REFERENCES kek(kek_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS secrets (
    secret_id BIGSERIAL PRIMARY KEY,
    secret_key VARCHAR(255) UNIQUE NOT NULL,
    fk_dek_id INT REFERENCES dek(dek_id) ON DELETE CASCADE,
    encrypted_secret_value BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    fk_service_id INT REFERENCES services(service_id) ON DELETE CASCADE
);

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'ammar') THEN
        CREATE USER ammar WITH PASSWORD '1234';
    END IF;
END
$$;

GRANT ALL PRIVILEGES ON DATABASE secretsvault TO ammar;
GRANT ALL ON SCHEMA public TO ammar;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ammar;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ammar;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO ammar;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO ammar;
