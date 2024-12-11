package utils

import (
	"crypto/rsa"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte(os.Getenv("JWT_SECRET"))
var tokenTTL = time.Minute * 15 // Token TTL (15 minutes)

func GenerateJWT(userID uint, role string) (string, error) {
	claims := jwt.MapClaims{
		"sub":  userID,                          // Subject (user ID)
		"role": role,                            // User's role
		"aud":  "your-application",              // Audience
		"iss":  "your-auth-server",              // Issuer
		"iat":  time.Now().Unix(),               // Issued at
		"exp":  time.Now().Add(tokenTTL).Unix(), // Expiration time
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	privateKey, err := LoadPrivateKey()
	if err != nil {
		return "", err
	}
	return token.SignedString(privateKey)
}

func GenerateRefreshToken(userID uint) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(7 * 24 * time.Hour).Unix(), // Expires in 7 days
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func LoadPrivateKey() (*rsa.PrivateKey, error) {
	privateKeyData, err := os.ReadFile("path/to/private.key")
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
}

func LoadPublicKey() (*rsa.PublicKey, error) {
	publicKeyData, err := os.ReadFile("path/to/public.key")
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
}
