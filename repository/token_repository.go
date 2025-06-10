package repository

import (
	"auth/model"
	"context"
	"gorm.io/gorm"
	"time"
)

type TokenRepository struct {
	DB *gorm.DB
}

func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{DB: db}
}

func (r *TokenRepository) SaveRefreshToken(ctx context.Context, token string, userID uint, expiresAt time.Time) error {
	refreshToken := model.RefreshToken{
		Token:     token,
		UserID:    userID,
		ExpiresAt: expiresAt,
	}
	return r.DB.WithContext(ctx).Create(&refreshToken).Error
}

func (r *TokenRepository) FindRefreshToken(ctx context.Context, token string) (*model.RefreshToken, error) {
	var refreshToken model.RefreshToken
	err := r.DB.WithContext(ctx).Where("token = ?", token).First(&refreshToken).Error
	return &refreshToken, err
}

func (r *TokenRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	return r.DB.WithContext(ctx).Where("token = ?", token).Delete(&model.RefreshToken{}).Error
}

func (r *TokenRepository) DeleteAllRefreshTokensForUser(ctx context.Context, userID uint) error {
	return r.DB.WithContext(ctx).Where("user_id = ?", userID).Delete(&model.RefreshToken{}).Error
}
