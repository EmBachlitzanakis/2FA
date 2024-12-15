package database

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"2FA/model"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// InitDB initializes the database connection
func InitDB() {
	dsn := fmt.Sprintf(
		"host=db user=%s password=%s dbname=%s port=5432 sslmode=disable TimeZone=Asia/Shanghai",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
	)
	log.Printf("DSN: %s", dsn) // Debugging the DSN

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		log.Fatalf("Failed to connect to database. \n %v", err)
		os.Exit(2)
	}

	log.Println("connected")

	// Run migrations
	log.Println("running migrations")
	if err := DB.AutoMigrate(&model.User{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA private key: %v", err)
	}

	// Convert private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Generate the corresponding public key in PEM format
	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatalf("Failed to marshal public key: %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Encrypt the private key using PGP encryption
	encryptionPassword := "your_password"
	encryptedPrivateKey, err := encryptWithPGP(privateKeyPEM, encryptionPassword, DB)
	if err != nil {
		log.Fatalf("Failed to encrypt private key: %v", err)
	}

	// Store the private and public keys in the database
	privateKeyRecord := model.Key{
		KeyType:             "private",
		EncryptedPrivateKey: encryptedPrivateKey,
	}

	publicKeyRecord := model.Key{
		KeyType:      "public",
		PublicKeyPEM: string(publicKeyPEM),
	}

	if err := DB.Create(&privateKeyRecord).Error; err != nil {
		log.Fatalf("Failed to insert encrypted private key into database: %v", err)
	}

	if err := DB.Create(&publicKeyRecord).Error; err != nil {
		log.Fatalf("Failed to insert public key into database: %v", err)
	}

	fmt.Println("Private and public keys successfully stored in the database")
}

// encryptWithPGP encrypts data using the pgp_sym_encrypt function in PostgreSQL
func encryptWithPGP(data []byte, encryptionPassword string, db *gorm.DB) ([]byte, error) {
	var encryptedData []byte

	query := `
	SELECT pgp_sym_encrypt(?, ?) AS encrypted_data
`
	if err := db.Raw(query, string(data), encryptionPassword).Scan(&encryptedData).Error; err != nil {
		return nil, fmt.Errorf("failed to encrypt data using pgp_sym_encrypt: %v", err)
	}

	return encryptedData, nil
}
