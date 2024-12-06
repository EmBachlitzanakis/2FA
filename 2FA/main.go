package main

import (
	"log"

	"2FA/database"
	"2FA/routes"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
)

func main() {
	// Initialize the database
	database.InitDB()

	// Initialize Fiber app
	app := fiber.New()
	app.Use(logger.New())

	// Set up routes
	routes.AuthRoutes(app)
	routes.ProtectedRoutes(app)
	app.Get("/test", func(c *fiber.Ctx) error {
		return c.SendString("Test route is working")
	})

	// Start the server
	if err := app.Listen(":8000"); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
