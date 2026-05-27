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

func InsertKEK(db *pgxpool.Pool, kek models.KeyEncryptionKey) error {
	_, err := db.Exec(context.Background(),
		`
		INSERT INTO kek(encrypted_kek, nonce)
		VALUES($1, $2)
		`,
		kek.KeyEncryptionKey, kek.Nonce,
	)
	return err
}

func InsertDEK(db *pgxpool.Pool, dek models.DataEncryptionKey) error {
	_, err := db.Exec(context.Background(),
		`
		INSERT INTO dek(encrypted_dek, nonce)
		VALUES($1, $2)
		`,
		dek.DataEncryptionKey, dek.Nonce,
	)
	return err
}
