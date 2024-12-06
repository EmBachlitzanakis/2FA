package routes

import (
	"2FA/handlers"
	"2FA/middleware"

	"github.com/gofiber/fiber/v2"
)

// Protected routes
func ProtectedRoutes(app *fiber.App) {
	protected := app.Group("/protected", middleware.JWTMiddleware)
	protected.Get("/dashboard", handlers.Dashboard)
}
