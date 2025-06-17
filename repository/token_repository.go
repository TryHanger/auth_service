package repository

import (
	"auth/model"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type TokenRepository interface {
	IsAccessTokenBlacklisted(ctx context.Context, jti string) (bool, error)
	FetchRefreshToken(ctx context.Context, token string) (model.TokenMetadata, error)
	StoreRefreshToken(ctx context.Context, token string, metadata model.TokenMetadata) error
	DeleteRefreshToken(ctx context.Context, token string) error
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
	BlacklistAccessToken(ctx context.Context, jti string, ttl time.Duration) error
	GetRefreshTokenByAccess(ctx context.Context, jti string) (string, error)
	StoreAccessToRefreshMapping(ctx context.Context, jti, refreshToken string, ttl time.Duration) error
}

type RedisTokenRepository struct {
	redis *redis.Client
}

func NewRedisTokenRepository(redisClient *redis.Client) *RedisTokenRepository {
	return &RedisTokenRepository{redis: redisClient}
}

func (r *RedisTokenRepository) StoreRefreshToken(ctx context.Context, token string, metadata model.TokenMetadata) error {
	key := fmt.Sprintf("refresh:%s", token) // добавляем префикс
	data, _ := json.Marshal(metadata)
	return r.redis.Set(ctx, key, data, time.Until(metadata.ExpiresAt)).Err()
}

func (r *RedisTokenRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	key := fmt.Sprintf("refresh:%s", token)
	return r.redis.Del(ctx, key).Err()
}

func (r *RedisTokenRepository) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	val, err := r.redis.Get(ctx, fmt.Sprintf("blacklist:%s", jti)).Result()
	if err == redis.Nil {
		return false, nil
	}
	return val == "true", err
}

func (r *RedisTokenRepository) BlacklistAccessToken(ctx context.Context, jti string, ttl time.Duration) error {
	return r.redis.Set(ctx, fmt.Sprintf("blacklist:%s", jti), "true", ttl).Err()
}

func (r *RedisTokenRepository) FetchRefreshToken(ctx context.Context, token string) (model.TokenMetadata, error) {
	val, err := r.redis.Get(ctx, fmt.Sprintf("refresh:%s", token)).Result()
	if err == redis.Nil {
		return model.TokenMetadata{}, errors.New("token not found")
	} else if err != nil {
		return model.TokenMetadata{}, err
	}

	var meta model.TokenMetadata
	if err := json.Unmarshal([]byte(val), &meta); err != nil {
		return model.TokenMetadata{}, err
	}
	return meta, nil
}

func (r *RedisTokenRepository) IsAccessTokenBlacklisted(ctx context.Context, jti string) (bool, error) {
	res, err := r.redis.Get(ctx, "blacklist:"+jti).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return res == "true", nil
}

func (r *RedisTokenRepository) GetRefreshTokenByAccess(ctx context.Context, jti string) (string, error) {
	key := fmt.Sprintf("access_to_refresh:%s", jti)
	return r.redis.Get(ctx, key).Result()
}

func (r *RedisTokenRepository) StoreAccessToRefreshMapping(ctx context.Context, jti, refreshToken string, ttl time.Duration) error {
	key := fmt.Sprintf("access_to_refresh:%s", jti)
	return r.redis.Set(ctx, key, refreshToken, ttl).Err()
}
