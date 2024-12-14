package routes

import (
	"2FA/database"
	"2FA/handlers"

	"github.com/gofiber/fiber/v2"
)

// Auth routes
func AuthRoutes(app *fiber.App) {
	auth := app.Group("/auth")
	auth.Post("/signup", handlers.SignUp)
	auth.Post("/login", func(c *fiber.Ctx) error {
		return handlers.Login(c, database.DB, "strong-encryption-password")
	})
	auth.Post("/enable-2fa", handlers.Enable2FA)
	auth.Post("/verify", handlers.Verify2FA)
}
