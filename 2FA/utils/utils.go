package utils

import (
	"crypto/rsa"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

var jwtKey = []byte(os.Getenv("JWT_SECRET"))
var tokenTTL = time.Minute * 15 // Token TTL (15 minutes)

func GenerateJWT(db *gorm.DB, encryptionPassword string, userID uint, role string, audience string, scopes []string) (string, error) {
	claims := jwt.MapClaims{
		"sub":   userID,                          // Subject (user ID)
		"role":  role,                            // User's role
		"aud":   audience,                        // Audience
		"iss":   "your-auth-server",              // Issuer
		"scope": scopes,                          // Define allowed scopes
		"iat":   time.Now().Unix(),               // Issued at
		"exp":   time.Now().Add(tokenTTL).Unix(), // Expiration time
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Load private key from database
	privateKey, err := LoadPrivateKey(db, encryptionPassword)
	if err != nil {
		return "", err
	}

	// Sign the token with the private key
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

// LoadPrivateKey fetches and decrypts the private key from PostgreSQL
func LoadPrivateKey(db *gorm.DB, encryptionPassword string) (*rsa.PrivateKey, error) {
	var privateKeyData []byte

	query := `
		SELECT pgp_sym_decrypt(encrypted_private_key, ?) AS private_key
		FROM keys
		WHERE key_type = 'private'
		LIMIT 1
	`
	// Fetch the decrypted private key
	if err := db.Raw(query, encryptionPassword).Scan(&privateKeyData).Error; err != nil {
		return nil, err
	}

	// Parse the private key
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// LoadPublicKey fetches and decrypts the public key from PostgreSQL
func LoadPublicKey(db *gorm.DB, encryptionPassword string) (*rsa.PublicKey, error) {
	var publicKeyData []byte

	query := `
		SELECT pgp_sym_decrypt(encrypted_private_key, ?) AS public_key
		FROM keys
		WHERE key_type = 'public'
		LIMIT 1
	`
	// Fetch the decrypted public key
	if err := db.Raw(query, encryptionPassword).Scan(&publicKeyData).Error; err != nil {
		return nil, err
	}

	// Parse the public key
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyData)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}
