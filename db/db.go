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
		select kek_id from kek where encrypted_kek='$1' and nonce='$2'
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
		select dek_id from dek where encrypted_dek='$1' and nonce='$2'
		`,
		dek.DataEncryptionKey, dek.Nonce,
	).Scan(&dekId)
	return dekId, err
}

func InsertSecret(db *pgxpool.Pool, secret models.Secret) error {
	_, err := db.Exec(context.Background(),
		`
		INSERT INTO secrets(fk_dek_id, secret_key, encrypted_secret_value, nonce)
		VALUES($1, $2, $3, $4)
		`,
		secret.DekIdFK, secret.SecretKey, secret.SecretValue, secret.Nonce,
	)
	return err
}
func FetchSecretByKey(db *pgxpool.Pool, secretKey string) (models.Secret, error) {
	var secret models.Secret
	err := db.QueryRow(
		context.Background(),
		`
        SELECT fk_dek_id, secret_key, encrypted_secret_value, nonce 
        FROM secrets 
        WHERE secret_key = $1
        `,
		secretKey, // Single quotes removed from $1
	).Scan(&secret.DekIdFK, &secret.SecretKey, &secret.SecretValue, &secret.Nonce) // Added missing reference ampersands (&)
	return secret, err
}

func FetchDEKbyId(db *pgxpool.Pool, DekId int) (models.DataEncryptionKey, error) {
	var dek models.DataEncryptionKey
	err := db.QueryRow(
		context.Background(),
		`
		select encrypted_dek, nonce from dek where dek_id = $1
		`,
		DekId,
	).Scan(&dek.DataEncryptionKey, &dek.Nonce)
	return dek, err
}

func FetchKEKbyId(db *pgxpool.Pool, KekId int) (models.KeyEncryptionKey, error) {
	var kek models.KeyEncryptionKey
	err := db.QueryRow(
		context.Background(),
		`
		select encrypted_kek, nonce from kek where kek_id = $1
		`,
		KekId,
	).Scan(&kek.KeyEncryptionKey, &kek.Nonce)
	return kek, err
}

func FetchSecretDecryptionPayload(db *pgxpool.Pool, secretKey string) (models.DecryptionPayload, error) {
	var payload models.DecryptionPayload

	err := db.QueryRow(
		context.Background(),
		`
        SELECT 
            s.encrypted_secret_value, 
            d.encrypted_dek, 
            k.encrypted_kek
        FROM secrets s
        JOIN dek d ON s.fk_dek_id = d.dek_id
        JOIN kek k ON d.fk_kek_id = k.kek_id
        WHERE s.secret_key = $1
        `,
		secretKey,
	).Scan(&payload.EncryptedSecretValue, &payload.EncryptedDEK, &payload.EncryptedKEK)

	return payload, err
}
