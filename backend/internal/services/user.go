package services

import (
	"errors"

	"cti-platform/internal/models"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type UserService struct {
	db *gorm.DB
}

type CreateUserRequest struct {
	Username  string `json:"username" binding:"required"`
	Email     string `json:"email" binding:"required,email"`
	Password  string `json:"password" binding:"required,min=8"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Role      string `json:"role" binding:"required,oneof=admin analyst viewer"`
}

type UpdateUserRequest struct {
	Email     *string `json:"email"`
	FirstName *string `json:"first_name"`
	LastName  *string `json:"last_name"`
	Role      *string `json:"role"`
	IsActive  *bool   `json:"is_active"`
}

func NewUserService(db *gorm.DB) *UserService {
	return &UserService{db: db}
}

func (s *UserService) CreateUser(req CreateUserRequest) (*models.User, error) {
	// Check if username already exists
	var existingUser models.User
	err := s.db.Where("username = ?", req.Username).First(&existingUser).Error
	if err == nil {
		return nil, errors.New("username already exists")
	}

	// Check if email already exists
	err = s.db.Where("email = ?", req.Email).First(&existingUser).Error
	if err == nil {
		return nil, errors.New("email already exists")
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	user := models.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Role:         req.Role,
		IsActive:     true,
	}

	err = s.db.Create(&user).Error
	if err != nil {
		return nil, err
	}

	// Remove password hash from response
	user.PasswordHash = ""
	return &user, nil
}

func (s *UserService) GetUser(id uint) (*models.User, error) {
	var user models.User
	err := s.db.First(&user, id).Error
	if err != nil {
		return nil, err
	}
	
	// Remove password hash from response
	user.PasswordHash = ""
	return &user, nil
}

func (s *UserService) GetUsers(page, limit int) ([]models.User, int64, error) {
	var users []models.User
	var total int64

	// Count total users
	err := s.db.Model(&models.User{}).Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	// Apply pagination
	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = 20
	}
	offset := (page - 1) * limit

	err = s.db.Offset(offset).Limit(limit).Order("created_at DESC").Find(&users).Error
	if err != nil {
		return nil, 0, err
	}

	// Remove password hashes from response
	for i := range users {
		users[i].PasswordHash = ""
	}

	return users, total, nil
}

func (s *UserService) UpdateUser(id uint, req UpdateUserRequest) (*models.User, error) {
	var user models.User
	err := s.db.First(&user, id).Error
	if err != nil {
		return nil, err
	}

	// Update fields if provided
	if req.Email != nil {
		// Check if email already exists for another user
		var existingUser models.User
		err = s.db.Where("email = ? AND id != ?", *req.Email, id).First(&existingUser).Error
		if err == nil {
			return nil, errors.New("email already exists")
		}
		user.Email = *req.Email
	}
	if req.FirstName != nil {
		user.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		user.LastName = *req.LastName
	}
	if req.Role != nil {
		user.Role = *req.Role
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}

	err = s.db.Save(&user).Error
	if err != nil {
		return nil, err
	}

	// Remove password hash from response
	user.PasswordHash = ""
	return &user, nil
}

func (s *UserService) DeleteUser(id uint) error {
	return s.db.Delete(&models.User{}, id).Error
}
