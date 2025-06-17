package utils

import (
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"strings"
	"time"
)

var jwtSecret = []byte("your_secret_key")

type CustomClaims struct {
	jwt.RegisteredClaims
}

func ValidateJWT(tokenStr string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, errors.New("invalid token")
	}
	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, errors.New("could not parse claims")
	}
	return claims, nil
}

func GenerateAccessToken(userID string) (string, string, error) {
	jti := uuid.NewString() // ты можешь использовать github.com/google/uuid
	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ID:        jti,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(jwtSecret)
	return signed, jti, err
}

func GenerateRefreshToken(userID string) (string, error) {
	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * 24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func ExtractToken(c *gin.Context) string {
	bearer := c.GetHeader("Authorization")
	if len(bearer) > 7 && strings.ToLower(bearer[0:7]) == "bearer " {
		return bearer[7:]
	}
	return ""
}
