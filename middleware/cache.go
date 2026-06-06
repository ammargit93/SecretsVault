package middleware

type CacheStruct struct {
	serviceName string
	secretValue []byte
}

var Cache map[string][]CacheStruct = make(map[string][]CacheStruct)
