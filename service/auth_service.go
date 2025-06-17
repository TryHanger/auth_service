package service

import (
	"auth/model"
	"auth/repository"
	"auth/utils"
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"strconv"
	"time"
)

type AuthService struct {
	userRepo  *repository.UserRepository
	tokenRepo repository.TokenRepository
}

func NewAuthService(userRepo *repository.UserRepository, redisTokenRepo repository.TokenRepository) *AuthService {
	return &AuthService{
		userRepo:  userRepo,
		tokenRepo: redisTokenRepo,
	}
}

func (s *AuthService) Register(email, phone, password string) error {
	_, err := s.userRepo.UserExists(email, phone)
	if err == nil {
		return errors.New("user already exists")
	}

	hashed, err := utils.HashPassword(password)
	if err != nil {
		return err
	}
	token := uuid.New().String()

	user := &model.User{
		PassHash:     hashed,
		IsConfirmed:  false,
		ConfirmToken: token,
	}

	if phone != "" {
		user.Phone = phone
	}

	if email != "" {
		user.Email = email
	}

	fmt.Printf("Confirm your email: http://localhost:8080/confirm?token=%s\n", token)

	return s.userRepo.Create(user)
}

func (s *AuthService) ConfirmEmail(token string) error {
	user, err := s.userRepo.FindByToken(token)
	if err != nil {
		return errors.New("invalid or expired token")
	}

	user.IsConfirmed = true
	user.ConfirmToken = ""

	return s.userRepo.UpdateUser(user)
}

func (s *AuthService) Login(ctx context.Context, identifier, password string) (map[string]string, error) {
	user, err := s.userRepo.UserExists(identifier, identifier)
	if err != nil {
		return nil, errors.New("user not found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(password)); err != nil {
		return nil, errors.New("invalid password")
	}

	userID := strconv.FormatUint(uint64(user.ID), 10)

	accessToken, jti, err := utils.GenerateAccessToken(userID)
	if err != nil {
		return nil, err
	}

	refreshToken, err := utils.GenerateRefreshToken(userID)
	if err != nil {
		return nil, err
	}

	metadata := model.TokenMetadata{
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		JTI:       jti,
	}
	err = s.tokenRepo.StoreRefreshToken(ctx, refreshToken, metadata)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, tokenString, jti string, exp time.Time) error {
	// Add to blacklist
	if err := s.tokenRepo.BlacklistAccessToken(ctx, jti, time.Until(exp)); err != nil {
		return err
	}

	// Delete refresh token
	if err := s.tokenRepo.DeleteRefreshToken(ctx, tokenString); err != nil {
		return err
	}

	return nil
}

func (s *AuthService) RefreshTokens(ctx context.Context, refreshToken string) (map[string]string, error) {
	if _, err := utils.ValidateJWT(refreshToken); err != nil {
		return nil, errors.New("invalid refresh token")
	}

	storedMeta, err := s.tokenRepo.FetchRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, errors.New("refresh token not found")
	}

	if err := s.tokenRepo.BlacklistAccessToken(ctx, storedMeta.JTI, 15*time.Minute); err != nil {
		return nil, err
	}

	if err := s.tokenRepo.DeleteRefreshToken(ctx, refreshToken); err != nil {
		return nil, err
	}

	accessToken, jti, err := utils.GenerateAccessToken(strconv.FormatUint(uint64(storedMeta.UserID), 10))
	if err != nil {
		return nil, err
	}

	newMeta := model.TokenMetadata{
		UserID:    storedMeta.UserID,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		JTI:       jti,
	}

	if err := s.tokenRepo.StoreRefreshToken(ctx, refreshToken, newMeta); err != nil {
		return nil, err
	}

	return map[string]string{
		"access_token": accessToken,
	}, nil
}
