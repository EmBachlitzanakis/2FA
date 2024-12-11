package middleware

import (
	"2FA/utils"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

func JWTMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Missing or invalid token"})
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Load public key for verification
	publicKey, err := utils.LoadPublicKey()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Error loading public key"})
	}

	// Parse and verify the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid claims"})
	}

	// Validate 'aud' claim
	if claims["aud"] != "your-application" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid audience"})
	}

	// Validate 'iss' claim
	if claims["iss"] != "your-auth-server" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid issuer"})
	}

	// Set user details in context
	c.Locals("userID", claims["sub"])
	c.Locals("userRole", claims["role"])

	return c.Next()
}

func AuthorizeRoles(roles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Extract the role from JWT token
		userRole := c.Locals("userRole")
		if userRole == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Role not found in token"})
		}

		// Check if the user's role is allowed
		for _, role := range roles {
			if userRole == role {
				return c.Next()
			}
		}

		// Role doesn't match
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Access denied"})
	}
}
