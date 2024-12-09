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

	if user.TwoFAEnabled {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Login successful. Please verify 2FA."})
	}

	tokenString, err := generateJWT(user.ID, user.Role.Name)
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

// // generateJWT creates a new JWT for a user
// func generateJWT(userID uint) (string, error) {
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
// 		"sub": userID,
// 		"iat": time.Now().Unix(),
// 		"exp": time.Now().Add(tokenTTL).Unix(),
// 	})
// 	return token.SignedString(jwtKey)
// }

func generateJWT(userID uint, role string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  userID,
		"role": role,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(tokenTTL).Unix(),
	})

	return token.SignedString(jwtKey)
}

// dashboard is a protected route for displaying the dashboard
func Dashboard(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Welcome to the dashboard"})
}
