package routes

import (
	"2FA/handlers"
	"2FA/middleware"

	"github.com/gofiber/fiber/v2"
)

// Protected routes
func ProtectedRoutes(app *fiber.App) {
	protected := app.Group("/protected", middleware.JWTMiddleware)
	// Role-based access for dashboard
	protected.Get("/dashboard", middleware.AuthorizeRoles("admin", "moderator"), handlers.Dashboard)

}
