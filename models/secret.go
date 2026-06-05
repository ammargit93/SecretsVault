package models

type Secret struct {
	SecretKey   string `json:"secret_key"`
	SecretValue []byte `json:"secret_value"`
	Nonce       []byte `json:"nonce"`
	DekIdFK     int    `json:"fk_dek_id"`
	ServiceId   int    `json:"fk_service_id"`
}

type SecretRequest struct {
	SecretKey   string `json:"secret_key"`
	SecretValue any    `json:"secret_value"`
}

type KeyEncryptionKey struct {
	KeyEncryptionKey []byte `json:"kek"`
	Nonce            []byte `json:"nonce"`
}

type DataEncryptionKey struct {
	DataEncryptionKey []byte `json:"dek"`
	Nonce             []byte `json:"nonce"`
	KekIdFK           int    `json:"fk_kek_id"`
}

type DecryptionPayload struct {
	EncryptedSecretValue []byte
	EncryptedDEK         []byte
	EncryptedKEK         []byte
}
