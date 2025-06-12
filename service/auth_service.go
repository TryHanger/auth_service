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
	"time"
)

type AuthService struct {
	userRepo  *repository.UserRepository
	tokenRepo *repository.TokenRepository
}

func NewAuthService(userRepo *repository.UserRepository, tokenRepo *repository.TokenRepository) *AuthService {
	return &AuthService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
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

	accessToken, err := utils.GenerateAccessToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("cannot create access token: %w", err)
	}

	refreshToken, err := utils.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("cannot create refresh token: %w", err)
	}

	if err := s.tokenRepo.SaveRefreshToken(ctx, refreshToken, user.ID, time.Now().Add(time.Hour*24*30)); err != nil {
		return nil, errors.New("failed to save refresh token")
	}

	return map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, userID uint, accessToken, refreshToken string) error {
	storedToken, err := s.tokenRepo.FindRefreshToken(ctx, refreshToken)
	if err != nil {
		return errors.New("invalid or expired refresh token")
	}

	if storedToken.UserID != userID {
		return errors.New("token doesnt belong to user")
	}

	if err := s.tokenRepo.DeleteRefreshToken(ctx, refreshToken); err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}
