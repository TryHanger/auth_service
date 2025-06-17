package model

import (
	"time"
)

type RefreshToken struct {
	ID        uint   `gorm:"primary_key"`
	Token     string `gorm:"uniqueIndex;default:null"`
	UserID    uint
	ExpiresAt time.Time
	CreatedAt time.Time
}

type TokenMetadata struct {
	UserID    uint
	ExpiresAt time.Time
	JTI       string
}
