package models

type Secret struct {
	SecretKey   []byte `json:"secret_key"`
	SecretValue []byte `json:"secret_value"`
	Nonce       []byte `json:"nonce"`
	DekIdFK     int    `json:"fk_dek_id"`
}

type SecretRequest struct {
	SecretKey   string
	SecretValue any
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
