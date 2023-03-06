package domain

type User struct {
	ID    string `json:"id" binding:"required"`
	Name  string `json:"name" binding:"required"`
	Email string `json:"email" binding:"required"`
}

type UserWithHashedPassword struct {
	User
	HashedPassword string
}
