package service

import (
	"github.com/gabrielseibel1/gaef-user-service/domain"
	"github.com/gabrielseibel1/gaef-user-service/store"
	"golang.org/x/crypto/bcrypt"
)

type Service interface {
	Create(user *domain.User, password string) (string, error)
	Login(email, password string) (string, error)
	Read(id string) (*domain.User, error)
	Update(user *domain.User) (*domain.User, error)
	Delete(id string) error
}

type storeService struct {
	store store.Store
}

func New(store store.Store) Service {
	return &storeService{
		store: store,
	}
}

func (ss storeService) Create(user *domain.User, password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", nil
	}
	var u = domain.UserWithHashedPassword{User: *user, HashedPassword: string(hash)}
	return ss.store.Create(&u)
}

func (ss storeService) Login(email, password string) (string, error) {
	u, err := ss.store.ReadSensitiveByEmail(email)
	if err != nil {
		return "", err
	}
	return u.ID, bcrypt.CompareHashAndPassword([]byte(u.HashedPassword), []byte(password))
}

func (ss storeService) Read(id string) (*domain.User, error) {
	return ss.store.ReadByID(id)
}

func (ss storeService) Update(user *domain.User) (*domain.User, error) {
	return ss.store.Update(user)
}

func (ss storeService) Delete(email string) error {
	return ss.store.Delete(email)
}
