package handlers

import (
	"os"
	"time"

	"2FA/database"
	"2FA/model"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// JWT secret and token expiration time
var jwtKey = []byte(os.Getenv("JWT_SECRET"))
var tokenTTL = time.Minute * 15 // Token TTL (15 minutes)

// signUp handles user registration
func SignUp(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error hashing password"})
	}

	user := model.User{Username: req.Username, Password: string(hashedPassword)}
	if err := database.DB.Create(&user).Error; err != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Username already exists"})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "User created successfully"})
}

// login handles user login (username/password verification)
func Login(c *fiber.Ctx) error {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.BodyParser(&credentials); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var user model.User
	if err := database.DB.Where("username = ?", credentials.Username).First(&user).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	// Check if 2FA is enabled
	if user.TwoFAEnabled {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Login successful. Please verify 2FA."})
	}

	// If 2FA is not enabled, issue JWT directly
	tokenString, err := generateJWT(user.ID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error generating token"})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"token": tokenString})
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

// generateJWT creates a new JWT for a user
func generateJWT(userID uint) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(tokenTTL).Unix(),
	})
	return token.SignedString(jwtKey)
}

// dashboard is a protected route for displaying the dashboard
func Dashboard(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Welcome to the dashboard"})
}
