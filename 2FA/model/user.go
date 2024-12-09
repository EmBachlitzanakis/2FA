package model

import "gorm.io/gorm"

type Role struct {
	gorm.Model
	Name string `json:"name"`
}

// User represents a user in the system
type User struct {
	gorm.Model
	Username     string `gorm:"uniqueIndex" json:"username"`
	Password     string `json:"-"` // Exclude from JSON responses
	Secret       string `json:"-"` // 2FA secret
	TwoFAEnabled bool   `json:"two_fa_enabled"`
	RefreshToken string `json:"-"`                               // Refresh token for user
	RoleID       uint   `gorm:"foreignKey:RoleID;references:ID"` // Optional: Foreign key to Role
	Role         Role   `gorm:"foreignKey:RoleID;references:ID"` // Optional: Include Role struct
}
