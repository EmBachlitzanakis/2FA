package model

import "gorm.io/gorm"

// User represents a user in the system
type User struct {
	gorm.Model
	Username     string `gorm:"uniqueIndex" json:"username"`
	Password     string `json:"-"` // Exclude from JSON responses
	Secret       string `json:"-"` // 2FA secret
	TwoFAEnabled bool   `json:"two_fa_enabled"`
	RefreshToken string `json:"-"` // Refresh token for user
}
