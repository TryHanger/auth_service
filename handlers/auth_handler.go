package handlers

import (
	"auth/service"
	"auth/utils"
	"context"
	"github.com/gin-gonic/gin"
	"github.com/nyaruka/phonenumbers"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type AuthHandler struct {
	service *service.AuthService
}

func NewAuthHandler(service *service.AuthService) *AuthHandler {
	return &AuthHandler{
		service: service,
	}
}

type RegisterInput struct {
	Identifier string `json:"identifier" binding:"required"`
	Password   string `json:"password" binding:"required,min=6"`
}

type LoginInput struct {
	Identifier string `json:"identifier" binding:"required"`
	Password   string `json:"password" binding:"required,min=6"`
}

type RefreshInput struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func isPhone(s string) bool {
	re := regexp.MustCompile(`^\+?[1-9]\d{9,14}$`)
	return re.MatchString(s)
}

func isEmail(s string) bool {
	// 1. Проверка формата email регулярным выражением
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(s) {
		return false
	}

	// 2. Извлечение доменной части
	parts := strings.Split(s, "@")
	if len(parts) != 2 { // Дополнительная проверка для безопасности
		return false
	}
	domain := parts[1]

	// 3. Настройка DNS-резолвера с таймаутом
	resolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: true, // Более строгая обработка ошибок
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 4. Проверка MX-записей
	if mx, err := resolver.LookupMX(ctx, domain); err == nil && len(mx) > 0 {
		return true
	}

	// 5. Проверка A-записей (как запасной вариант)
	if ips, err := resolver.LookupIPAddr(ctx, domain); err == nil && len(ips) > 0 {
		return true
	}

	return false
}

func isKazakhstanMobileNumber(input string) (string, bool) {
	parsed, err := phonenumbers.Parse(input, "KZ")
	if err != nil {
		return "", false
	}

	if phonenumbers.GetRegionCodeForNumber(parsed) != "KZ" {
		return "", false
	}

	if phonenumbers.GetNumberType(parsed) != phonenumbers.MOBILE {
		return "", false
	}

	formatted := phonenumbers.Format(parsed, phonenumbers.E164)
	return formatted, true
}

func (h *AuthHandler) Register(c *gin.Context) {
	var input RegisterInput

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := ""
	phone := ""

	switch {
	case isEmail(input.Identifier):
		email = input.Identifier
	case isPhone(input.Identifier):
		if formattedPhone, ok := isKazakhstanMobileNumber(input.Identifier); ok {
			phone = formattedPhone
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid Kazakhstan mobile number"})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "identifier must be a valid email or phone number"})
		return
	}

	err := h.service.Register(email, phone, input.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "user created"})
}

func (h *AuthHandler) ConfirmEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	err := h.service.ConfirmEmail(token)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "email confirmed"})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tokens, err := h.service.Login(c.Request.Context(), input.Identifier, input.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tokens)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "refresh_token required"})
		return
	}

	// Получаем access_token из заголовка
	tokenString := utils.ExtractToken(c)
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no token found"})
		return
	}

	claims, err := utils.ValidateJWT(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	jti := claims.ID
	exp := time.Unix(claims.ExpiresAt.Unix(), 0)

	err = h.service.Logout(c.Request.Context(), req.RefreshToken, jti, exp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "logout failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var input RefreshInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	tokens, err := h.service.RefreshTokens(c.Request.Context(), input.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tokens)
}
