package main

import (
	"auth/database"
	"auth/handlers"
	"auth/middleware"
	"auth/model"
	"auth/repository"
	"auth/service"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func main() {
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})

	database.Connect()
	database.DB.AutoMigrate(&model.User{}, &model.RefreshToken{})

	tokenRepo := repository.NewTokenRepository(database.DB, redisClient)
	userRepo := repository.NewUserRepository(database.DB)
	authService := service.NewAuthService(userRepo, tokenRepo)
	authHandler := handlers.NewAuthHandler(authService)

	r := gin.Default()

	r.POST("/register", authHandler.Register)
	r.GET("/confirm", authHandler.ConfirmEmail)
	r.POST("/login", authHandler.Login)

	r.GET("/profile", middleware.JWTAuthMiddleware(), func(c *gin.Context) {
		userID := c.MustGet("user_id").(uint)
		c.JSON(200, gin.H{
			"user_id": userID,
		})
	})
	//r.POST("/refresh", authHandler.RefreshToken)

	r.Run("localhost:8080")
}
