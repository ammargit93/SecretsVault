package models

type Secret struct {
	SecretKey   []byte `json:"secret_key"`
	SecretValue []byte `json:"secret_value"`
	Nonce       []byte `json:"nonce"`
}

type KeyEncryptionKey struct {
	KeyEncryptionKey []byte `json:"kek"`
	Nonce            []byte `json:"nonce"`
}

type DataEncryptionKey struct {
	DataEncryptionKey []byte `json:"dek"`
	Nonce             []byte `json:"nonce"`
}
