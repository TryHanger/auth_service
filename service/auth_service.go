package service

import (
	"auth/model"
	"auth/repository"
	"auth/utils"
	"context"
	"encoding/json"
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

func (s *AuthService) Login(ctx context.Context, identifier, password, ip, userAgent string) (map[string]string, error) {
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

	session := model.Session{
		UserID:       user.ID,
		IPAddress:    ip,
		UserAgent:    userAgent,
		JTI:          jti,
		RefreshToken: refreshToken,
		ExpiresAt:    time.Now().Add(30 * 24 * time.Hour),
		CreatedAt:    time.Now(),
	}

	err = s.tokenRepo.StoreSession(ctx, session)
	if err != nil {
		return nil, err
	}

	_ = s.tokenRepo.CleanupExpiredSessions(ctx, user.ID)

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

func (s *AuthService) GetUserSessions(ctx context.Context, userID string) ([]model.Session, error) {
	return s.tokenRepo.GetSessionsByUser(ctx, userID)
}

func (s *AuthService) LogoutSession(ctx context.Context, userID uint, jti string) error {
	sessionKey := fmt.Sprintf("session:%d:%s", userID, jti)
	val, err := s.tokenRepo.GetRawSession(ctx, sessionKey)
	if err != nil {
		return err
	}

	var session model.Session
	if err := json.Unmarshal([]byte(val), &session); err != nil {
		return err
	}

	if err := s.tokenRepo.DeleteRefreshToken(ctx, session.RefreshToken); err != nil {
		return err
	}
	return s.tokenRepo.DeleteSession(ctx, sessionKey)
}

func (s *AuthService) LogoutAllSession(ctx context.Context, userID uint) error {
	sessions, err := s.tokenRepo.GetSessionsByUser(ctx, strconv.FormatUint(uint64(userID), 10))
	if err != nil {
		return err
	}

	for _, session := range sessions {
		if err := s.tokenRepo.DeleteRefreshToken(ctx, session.RefreshToken); err != nil {
			continue
		}
		key := fmt.Sprintf("session:%d:%s", userID, session.JTI)
		_ = s.tokenRepo.DeleteSession(ctx, key)
	}
	return nil
}

func (s *AuthService) LogoutOtherSessions(ctx context.Context, userID, currentJTI string) error {
	sessions, err := s.tokenRepo.GetSessionsByUser(ctx, userID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		if session.JTI == currentJTI {
			continue
		}

		_ = s.tokenRepo.BlacklistAccessToken(ctx, session.JTI, time.Until(session.ExpiresAt))
		_ = s.tokenRepo.DeleteRefreshToken(ctx, session.RefreshToken)

		key := fmt.Sprintf("session:%s:%s", userID, session.JTI)
		_ = s.tokenRepo.DeleteSession(ctx, key)
	}
	return nil
}

func (s *AuthService) GetSession(ctx context.Context, userID uint, jti string) (*model.Session, error) {
	return s.tokenRepo.FetchSession(ctx, userID, jti)
}
