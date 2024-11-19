package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	gorm.Model
	Username     string `gorm:"uniqueIndex" json:"username"`
	Password     string `json:"password"`
	Secret       string `json:"secret"`
	TwoFAEnabled bool   `json:"two_fa_enabled"`
}

var db *gorm.DB

func main() {
	var err error
	// Initialize the database connection
	db, err = gorm.Open(sqlite.Open("users.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect to database")
	}

	// Migrate the schema
	err = db.AutoMigrate(&User{})
	if err != nil {
		panic("failed to migrate database")
	}

	router := gin.Default()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	auth := router.Group("/auth")
	auth.POST("/signup", signUp)
	auth.POST("/login", login)
	auth.POST("/enable-2fa", enable2FA)
	auth.POST("/verify", verify2FA)

	router.Run(":8080")
}

// signUp handles user registration
func signUp(c *gin.Context) {
	var newUser User
	if err := c.ShouldBindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create the user in the database
	if err := db.Create(&newUser).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
}

// login handles user login
func login(c *gin.Context) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find the user in the database
	var user User
	if err := db.Where("username = ? AND password = ?", credentials.Username, credentials.Password).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

// verify2FA handles 2FA code verification
func verify2FA(c *gin.Context) {
	var verification struct {
		Username string `json:"username"`
		Code     string `json:"code"`
	}

	if err := c.ShouldBindJSON(&verification); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find the user in the database
	var user User
	if err := db.Where("username = ?", verification.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Verify the provided code
	valid := totp.Validate(verification.Code, user.Secret)
	if !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid 2FA code"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "2FA code is valid"})
}

// enable2FA generates a secret and QR code for 2FA setup
func enable2FA(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find the user in the database
	var user User
	if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Generate a secret for the user
	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "MyApp",
		AccountName: user.Username,
		Period:      60,
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating QR code"})
		return
	}

	// Save the secret in the user object
	user.Secret = secret.Secret()
	user.TwoFAEnabled = true
	db.Save(&user)

	c.JSON(http.StatusOK, gin.H{"secret": secret.Secret(), "url": secret.URL()})
}
