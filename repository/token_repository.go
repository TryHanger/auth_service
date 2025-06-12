package repository

import (
	"auth/model"
	"context"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
	"time"
)

type TokenRepository struct {
	DB    *gorm.DB
	redis *redis.Client
}

func NewTokenRepository(db *gorm.DB, redisClient *redis.Client) *TokenRepository {
	return &TokenRepository{
		DB:    db,
		redis: redisClient,
	}
}

func (r *TokenRepository) SaveRefreshToken(ctx context.Context, token string, userID uint, expiresAt time.Time) error {
	return r.DB.Create(&model.RefreshToken{
		Token:     token,
		UserID:    userID,
		ExpiresAt: expiresAt,
	}).Error
}

func (r *TokenRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	return r.DB.Where("token = ?", token).Delete(&model.RefreshToken{}).Error
}

func (r *TokenRepository) DeleteAllRefreshTokensForUser(ctx context.Context, userID uint) error {
	return r.DB.Where("user_id = ?", userID).Delete(&model.RefreshToken{}).Error
}

func (r *TokenRepository) FindRefreshToken(ctx context.Context, token string) (*model.RefreshToken, error) {
	var refreshToken model.RefreshToken
	err := r.DB.Where("token = ?", token).First(&refreshToken).Error
	return &refreshToken, err
}
