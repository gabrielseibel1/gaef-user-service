package domain

import "golang.org/x/crypto/bcrypt"

type User struct {
	ID    string `json:"id" binding:"required"`
	Name  string `json:"name" binding:"required"`
	Email string `json:"email" binding:"required"`
}

type UserWithHashedPassword struct {
	User
	HashedPassword string
}

type PasswordHasherVerifier struct{}

func (phv PasswordHasherVerifier) GenerateFromPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func (phv PasswordHasherVerifier) CompareHashAndPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
