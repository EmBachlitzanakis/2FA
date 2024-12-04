package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	gorm.Model
	Username     string `gorm:"uniqueIndex" json:"username"`
	Password     string `json:"-"` // Exclude from JSON responses
	Secret       string `json:"-"` // 2FA secret
	TwoFAEnabled bool   `json:"two_fa_enabled"`
}

var (
	db       *gorm.DB
	jwtKey   = []byte(os.Getenv("JWT_SECRET")) // Load from environment variable
	dbConn   = os.Getenv("DB_CONN_STRING")     // MS SQL Server connection string
	issuer   = "MyApp"                         // For TOTP generation
	tokenTTL = time.Minute * 15                // Token TTL (15 minutes)
)

func main() {
	var err error
	// Initialize the database connection (MS SQL)
	db, err = gorm.Open(sqlserver.Open(dbConn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Migrate the schema
	if err := db.AutoMigrate(&User{}); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// Initialize Gin router
	router := gin.Default()
	router.Use(gin.Recovery())
	router.Use(gin.Logger())

	// Authentication-related routes
	auth := router.Group("/auth")
	{
		auth.POST("/signup", signUp)        // User registration
		auth.POST("/enable-2fa", enable2FA) // Enable 2FA for user
		auth.POST("/login", login)          // Username/password login
		auth.POST("/verify-2fa", verify2FA) // Verify 2FA and issue JWT token
	}

	// Protected routes
	protected := router.Group("/protected")
	protected.Use(jwtMiddleware()) // JWT middleware applied here
	{
		protected.GET("/dashboard", dashboard) // Protected route, requires valid JWT
	}

	// Run the server
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// signUp handles user registration
func signUp(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}

	user := User{Username: req.Username, Password: string(hashedPassword)}
	if err := db.Create(&user).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created successfully"})
}

// login handles user login (username/password verification)
func login(c *gin.Context) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := db.Where("username = ?", credentials.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check if 2FA is enabled
	if user.TwoFAEnabled {
		c.JSON(http.StatusOK, gin.H{"message": "Login successful. Please verify 2FA."})
		return
	}

	// If 2FA is not enabled, issue JWT directly
	tokenString, err := generateJWT(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// enable2FA generates a secret for 2FA setup
func enable2FA(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user.Username,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating 2FA secret"})
		return
	}

	user.Secret = secret.Secret()
	user.TwoFAEnabled = true
	db.Save(&user)

	c.JSON(http.StatusOK, gin.H{"secret": secret.Secret(), "url": secret.URL()})
}

// verify2FA handles 2FA verification and JWT generation
func verify2FA(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Code     string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user User
	if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if !totp.Validate(req.Code, user.Secret) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid 2FA code"})
		return
	}

	tokenString, err := generateJWT(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// jwtMiddleware verifies the JWT token for protected routes
func jwtMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid token"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// generateJWT creates a new JWT for a user
func generateJWT(userID uint) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(tokenTTL).Unix(),
	})
	return token.SignedString(jwtKey)
}

// dashboard is a protected route
func dashboard(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Welcome to the dashboard"})
}
