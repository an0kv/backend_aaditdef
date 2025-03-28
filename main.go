package main

import (
	"context"
	"log"
	"time"

	"backend/config"
	"backend/database"
	"backend/handlers"
	"backend/middleware"
	"backend/scheduler"

	"github.com/gin-gonic/gin"
)

func main() {

	cfg := config.LoadConfig()

	db, err := database.ConnectToMongoDB(cfg.MongoURI)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	defer db.Disconnect(context.TODO())

	go scheduler.StartFileScanner("/path/to/scan", 20*time.Minute)

	r := gin.Default()

	public := r.Group("/")
	{
		public.POST("/register", handlers.RegisterUser)
		public.POST("/login", handlers.LoginUser)
	}

	protected := r.Group("/")
	protected.Use(middleware.AuthMiddleware(cfg.JWTSecret))
	{
		protected.POST("/scan", handlers.ScanFile)
		protected.POST("/scan-phone-files", handlers.ScanPhoneFiles)
		protected.GET("/scan/:id", handlers.GetScanResult)
	}

	log.Println("Starting server on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
