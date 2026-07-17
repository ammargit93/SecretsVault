package db

import (
	"context"
	"log"
	"secretsvault/models"

	"github.com/jackc/pgx/v5/pgxpool"
)

func InitDB() *pgxpool.Pool {
	conn, err := pgxpool.New(
		context.Background(),
		"postgres://ammar:1234@localhost:5432/secretsvault",
	)
	if err != nil {
		log.Fatal(err)
	}
	return conn
}

func InsertService(db *pgxpool.Pool, service models.Service) error {
	_, err := db.Exec(context.Background(),
		`
		INSERT INTO services(service_name, service_api_key, service_role)
		VALUES($1, $2, $3)
		`,
		service.ServiceName, service.ServiceAPIKey, service.ServiceRole,
	)
	return err
}

func FetchService(db *pgxpool.Pool, serviceName, serviceRole string) (string, error) {
	var serviceAPIKey string
	err := db.QueryRow(
		context.Background(),
		`
		select service_api_key from services where service_name=$1 and service_role=$2
		`,
		serviceName, serviceRole,
	).Scan(&serviceAPIKey)
	return serviceAPIKey, err
}

func InsertKEK(db *pgxpool.Pool, kek models.KeyEncryptionKey) (int, error) {
	var id int
	err := db.QueryRow(context.Background(),
		`INSERT INTO kek (encrypted_kek, nonce) VALUES ($1, $2) RETURNING kek_id`,
		kek.KeyEncryptionKey, kek.Nonce,
	).Scan(&id)
	return id, err
}

func FetchKEK(db *pgxpool.Pool, kek models.KeyEncryptionKey) (int, error) {
	var kekId int
	err := db.QueryRow(
		context.Background(),
		`
		select kek_id from kek where encrypted_kek=$1 and nonce=$2
		`,
		kek.KeyEncryptionKey, kek.Nonce,
	).Scan(&kekId)
	return kekId, err
}

func InsertDEK(db *pgxpool.Pool, dek models.DataEncryptionKey) (int, error) {
	var id int
	err := db.QueryRow(context.Background(),
		`INSERT INTO dek (encrypted_dek, nonce, fk_kek_id) VALUES ($1, $2, $3) RETURNING dek_id`,
		dek.DataEncryptionKey, dek.Nonce, dek.KekIdFK,
	).Scan(&id)
	return id, err
}

func FetchDEK(db *pgxpool.Pool, dek models.DataEncryptionKey) (int, error) {
	var dekId int
	err := db.QueryRow(
		context.Background(),
		`
		select dek_id from dek where encrypted_dek=$1 and nonce=$2
		`,
		dek.DataEncryptionKey, dek.Nonce,
	).Scan(&dekId)
	return dekId, err
}

func InsertSecret(db *pgxpool.Pool, secret models.Secret) error {
	_, err := db.Exec(context.Background(),
		`
		INSERT INTO secrets(fk_dek_id, secret_key, encrypted_secret_value, nonce, fk_service_id)
		VALUES($1, $2, $3, $4, $5)
		`,
		secret.DekIdFK, secret.SecretKey, secret.SecretValue, secret.Nonce, secret.ServiceId,
	)
	return err
}

func FetchSecretDecryptionPayload(db *pgxpool.Pool, secretKey string, serviceName string) (models.DecryptionPayload, error) {
	var payload models.DecryptionPayload

	err := db.QueryRow(
		context.Background(),
		`
		SELECT
			s.encrypted_secret_value,
			d.encrypted_dek,
			k.encrypted_kek
		FROM secrets s
		JOIN services sv
			ON s.fk_service_id = sv.service_id
		JOIN dek d
			ON s.fk_dek_id = d.dek_id
		JOIN kek k
			ON d.fk_kek_id = k.kek_id
		WHERE s.secret_key = $1
		AND sv.service_name = $2
		`,
		secretKey,
		serviceName,
	).Scan(
		&payload.EncryptedSecretValue,
		&payload.EncryptedDEK,
		&payload.EncryptedKEK,
	)
	return payload, err
}

func FetchServiceId(db *pgxpool.Pool, serviceName string) (int, error) {
	var id int

	err := db.QueryRow(
		context.Background(),
		`
        SELECT service_id
        FROM services 
        WHERE service_name = $1
        `,
		serviceName,
	).Scan(&id)
	return id, err
}
func FetchSecretsForService(db *pgxpool.Pool, serviceName string) ([]string, error) {
	rows, err := db.Query(
		context.Background(),
		`
		SELECT secret_key
		FROM secrets
		WHERE fk_service_id = (
			SELECT service_id
			FROM services
			WHERE service_name = $1
		)
		`,
		serviceName,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var secretsList []string
	for rows.Next() {
		var secretName string
		if err := rows.Scan(&secretName); err != nil {
			return nil, err
		}
		log.Println(secretName, serviceName)
		secretsList = append(secretsList, secretName)
	}
	return secretsList, rows.Err()
}

func FetchKekIdForSecret(db *pgxpool.Pool, secretKey string, serviceName string) (int, error) {
	var kekId int
	err := db.QueryRow(
		context.Background(),
		`
		SELECT d.fk_kek_id
		FROM secrets s
		JOIN services sv ON s.fk_service_id = sv.service_id
		JOIN dek d ON s.fk_dek_id = d.dek_id
		WHERE s.secret_key = $1 AND sv.service_name = $2
		`,
		secretKey,
		serviceName,
	).Scan(&kekId)
	return kekId, err
}

func DeleteKEK(db *pgxpool.Pool, kekId int) error {
	_, err := db.Exec(
		context.Background(),
		`DELETE FROM kek WHERE kek_id = $1`,
		kekId,
	)
	return err
}

func UpdateSecret(db *pgxpool.Pool, secretKey string, serviceName string, encryptedValue []byte, nonce []byte) error {
	_, err := db.Exec(
		context.Background(),
		`
		UPDATE secrets
		SET encrypted_secret_value = $1, nonce = $2
		WHERE secret_key = $3
		AND fk_service_id = (
			SELECT service_id FROM services WHERE service_name = $4
		)
		`,
		encryptedValue,
		nonce,
		secretKey,
		serviceName,
	)
	return err
}

func FetchActiveDekIdForService(db *pgxpool.Pool, serviceId int) (int, error) {
	var id int
	err := db.QueryRow(
		context.Background(),
		`
		SELECT fk_dek_id
		FROM secrets
		WHERE fk_service_id = $1
		LIMIT 1
		`,
		serviceId,
	).Scan(&id)
	return id, err
}

func FetchDEKAndKEKByDekId(db *pgxpool.Pool, dekId int) (models.DecryptionPayload, error) {
	var payload models.DecryptionPayload
	err := db.QueryRow(
		context.Background(),
		`
		SELECT d.encrypted_dek, k.encrypted_kek
		FROM dek d
		JOIN kek k ON d.fk_kek_id = k.kek_id
		WHERE d.dek_id = $1
		`,
		dekId,
	).Scan(&payload.EncryptedDEK, &payload.EncryptedKEK)
	return payload, err
}

func DeleteSecret(db *pgxpool.Pool, secretKey string, serviceName string) error {
	_, err := db.Exec(
		context.Background(),
		`
		DELETE FROM secrets
		WHERE secret_key = $1
		AND fk_service_id = (
			SELECT service_id FROM services WHERE service_name = $2
		)
		`,
		secretKey,
		serviceName,
	)
	return err
}
