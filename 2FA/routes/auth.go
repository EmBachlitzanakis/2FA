package routes

import (
	"2FA/handlers"

	"github.com/gofiber/fiber/v2"
)

// Auth routes
func AuthRoutes(app *fiber.App) {
	auth := app.Group("/auth")
	auth.Post("/signup", handlers.SignUp)
	auth.Post("/login", handlers.Login)
	auth.Post("/enable-2fa", handlers.Enable2FA)
	auth.Post("/verify", handlers.Verify2FA)
}
