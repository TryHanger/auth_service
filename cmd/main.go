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

	tokenRepo := repository.NewRedisTokenRepository(redisClient)
	userRepo := repository.NewUserRepository(database.DB)
	authService := service.NewAuthService(userRepo, tokenRepo)
	authHandler := handlers.NewAuthHandler(authService)
	authMiddleware := middleware.NewAuthMiddleware(tokenRepo)

	r := gin.Default()

	r.POST("/register", authHandler.Register)
	r.GET("/confirm", authHandler.ConfirmEmail)
	r.POST("/login", authHandler.Login)

	auth := r.Group("/auth")
	auth.Use(authMiddleware.JWTAuthMiddleware())
	{
		auth.GET("/profile", func(c *gin.Context) {
			userID := c.MustGet("user_id").(string)
			c.JSON(200, gin.H{
				"user_id": userID,
			})
		})
		auth.GET("/sessions", authHandler.GetSessions)
		auth.DELETE("/logout/:jti", authHandler.LogoutSession)
		auth.DELETE("/sessions", authHandler.LogoutAll)
		auth.POST("/logout/others", authHandler.LogoutOtherSessions)
		auth.GET("/sessions/:jti", authHandler.GetSession)
	}

	//r.POST("/logout", authHandler.Logout)
	r.POST("/refresh", authHandler.RefreshToken)

	r.Run("localhost:8080")
}
