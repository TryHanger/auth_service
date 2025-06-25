package model

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Phone        string `gorm:"uniqueIndex;default:null"`
	Email        string `gorm:"uniqueIndex;default:null"`
	PassHash     string
	IsConfirmed  bool
	ConfirmToken string
}
