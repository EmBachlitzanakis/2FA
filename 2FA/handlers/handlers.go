package handlers

import (
	"os"

	"2FA/database"
	"2FA/model"
	"2FA/utils"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// JWT secret and token expiration time
var jwtKey = []byte(os.Getenv("JWT_SECRET"))

//var tokenTTL = time.Minute * 15 // Token TTL (15 minutes)

// signUp handles user registration
func SignUp(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error hashing password"})
	}
	var role model.Role
	if err := database.DB.Where("name = ?", req.Role).First(&role).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error checking role"})
	}

	user := model.User{Username: req.Username, Password: string(hashedPassword), Role: role}
	if err := database.DB.Create(&user).Error; err != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Username already exists"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "User created successfully"})
}

// login handles user login (username/password verification)
func Login(c *fiber.Ctx, db *gorm.DB, encryptionPassword string) error {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&credentials); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var user model.User
	if err := db.Where("username = ?", credentials.Username).First(&user).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	if user.TwoFAEnabled {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Login successful. Please verify 2FA."})
	}

	// Fetch permissions/scopes from the database based on the user's role or ID
	var userPermissions []string
	if err := db.Model(&user).Association("Permissions").Find(&userPermissions); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error fetching permissions"})
	}

	// Assign the permissions as scopes
	scopes := userPermissions

	// Generate access token with dynamic scopes
	accessToken, err := utils.GenerateJWT(db, encryptionPassword, user.ID, user.Role.Name, "your-application", scopes)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error generating access token"})
	}

	// Generate refresh token
	refreshToken, err := utils.GenerateRefreshToken(user.ID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error generating refresh token"})
	}

	// Store refresh token securely
	user.RefreshToken = refreshToken
	if err := db.Save(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error saving refresh token"})
	}

	// Return the tokens
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// enable2FA generates a secret for 2FA setup
func Enable2FA(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var user model.User
	if err := database.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	secret, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "MyApp",
		AccountName: user.Username,
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error generating 2FA secret"})
	}

	user.Secret = secret.Secret()
	user.TwoFAEnabled = true
	database.DB.Save(&user)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"secret": secret.Secret(), "url": secret.URL()})
}

func Verify2FA(c *fiber.Ctx) error {
	// Parse request body
	var req struct {
		Username string `json:"username"`
		Code     string `json:"code"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var user model.User
	if err := database.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	if !totp.Validate(req.Code, user.Secret) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid 2FA code"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "2FA code is valid"})
}

func RefreshToken(c *fiber.Ctx, db *gorm.DB, encryptionPassword string) error {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	// Parse and validate the refresh token
	token, err := jwt.Parse(req.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil // Use your secret or public key for validation if required
	})

	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid refresh token"})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["sub"] == nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token claims"})
	}

	userID := uint(claims["sub"].(float64))

	// Verify refresh token matches the stored token (if stored)
	var user model.User
	if err := db.First(&user, userID).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "User not found"})
	}

	if user.RefreshToken != req.RefreshToken {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid refresh token"})
	}

	// Fetch permissions/scopes from the database based on the user's role or ID
	var userPermissions []string
	if err := db.Model(&user).Association("Permissions").Find(&userPermissions); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error fetching permissions"})
	}

	// Assign the permissions as scopes
	scopes := userPermissions

	// Generate a new access token
	accessToken, err := utils.GenerateJWT(db, encryptionPassword, user.ID, user.Role.Name, "your-application", scopes)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error generating access token"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"access_token": accessToken})
}

// dashboard is a protected route for displaying the dashboard
func Dashboard(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Welcome to the dashboard"})
}
