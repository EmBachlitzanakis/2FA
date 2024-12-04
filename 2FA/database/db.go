package database

import (
	"log"
	"os"

	"2FA/model"

	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
)

var DB *gorm.DB

// InitDB initializes the database connection
func InitDB() {
	var err error
	dbConn := os.Getenv("DB_CONN_STRING") // MS SQL Server connection string
	DB, err = gorm.Open(sqlserver.Open(dbConn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Optionally, you can also perform migrations here
	if err := DB.AutoMigrate(&model.User{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
}
