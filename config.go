package auth_service

import "os"

type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

func GetRedisConfig() *RedisConfig {
	return &RedisConfig{
		Host:     os.Getenv("REDIS_HOST"),
		Port:     os.Getenv("REDIS_PORT"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	}
}

const (
	AccessTokenExpire  = 60
	RefreshTokenExpire = 60 * 2
)
