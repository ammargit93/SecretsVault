package middleware

type CacheStruct struct {
	ServiceName string
	SecretValue []byte
}

var Cache map[string][]CacheStruct = make(map[string][]CacheStruct)
