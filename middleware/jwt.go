package middleware

import (
	"auth/repository"
	"auth/utils"
	"github.com/gin-gonic/gin"
	"net/http"
	"strings"
)

type AuthMiddleware struct {
	TokenRepo repository.TokenRepository
}

func NewAuthMiddleware(tokenRepo repository.TokenRepository) *AuthMiddleware {
	return &AuthMiddleware{
		TokenRepo: tokenRepo,
	}
}

func (m *AuthMiddleware) JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "No Authorization header found"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		claims, err := utils.ValidateJWT(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		jti := claims.ID
		isBlacklisted, err := m.TokenRepo.IsBlacklisted(c.Request.Context(), jti)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if isBlacklisted {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token is blacklisted"})
			return
		}

		c.Set("user_id", claims.Subject)
		c.Next()
	}
}
