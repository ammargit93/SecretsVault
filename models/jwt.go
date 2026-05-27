package models

import "github.com/golang-jwt/jwt/v4"

type JWTClaims struct {
	ServiceName string `json:"service_name"`
	ServiceRole string `json:"service_role"`
	jwt.RegisteredClaims
}
