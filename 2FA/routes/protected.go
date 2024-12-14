package routes

import (
	"2FA/handlers"
	"2FA/middleware"

	"github.com/gofiber/fiber/v2"
)

func ProtectedRoutes(app *fiber.App) {
	protected := app.Group("/protected")

	// Dashboard: Requires JWT, specific role(s), and scope(s)
	protected.Get("/dashboard",
	//	middleware.JWTMiddleware("your-application", []string{"read:dashboard"}), // Validates audience and scopes
		middleware.AuthorizeRoles("admin", "moderator"),                          // Validates roles
		handlers.Dashboard,
	)
}
