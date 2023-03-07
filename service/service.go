package service

import (
	"github.com/gabrielseibel1/gaef-user-service/domain"
)

// dependencies

type PasswordHasher interface {
	GenerateFromPassword(password string) (string, error)
}
type PasswordVerifier interface {
	CompareHashAndPassword(hashedPassword, password string) error
}
type Creator interface {
	Create(user *domain.UserWithHashedPassword) (string, error)
}
type ByIDReader interface {
	ReadByID(id string) (*domain.User, error)
}
type ByEmailReader interface {
	ReadSensitiveByEmail(email string) (*domain.UserWithHashedPassword, error)
}
type Updater interface {
	Update(user *domain.User) (*domain.User, error)
}
type Deleter interface {
	Delete(id string) error
}

// implementation

type Service struct {
	passwordHasher   PasswordHasher
	passwordVerifier PasswordVerifier
	creator          Creator
	byIDReader       ByIDReader
	byEmailReader    ByEmailReader
	updater          Updater
	deleter          Deleter
}

func New(passwordHasher PasswordHasher, passwordVerifier PasswordVerifier, creator Creator, byIDReader ByIDReader, byEmailReader ByEmailReader, updater Updater, deleter Deleter) *Service {
	return &Service{
		passwordHasher:   passwordHasher,
		passwordVerifier: passwordVerifier,
		creator:          creator,
		byIDReader:       byIDReader,
		byEmailReader:    byEmailReader,
		updater:          updater,
		deleter:          deleter,
	}
}

func (s Service) Create(user *domain.User, password string) (string, error) {
	hash, err := s.passwordHasher.GenerateFromPassword(password)
	if err != nil {
		return "", err
	}
	u := domain.UserWithHashedPassword{User: *user, HashedPassword: hash}
	return s.creator.Create(&u)
}

func (ss Service) Login(email, password string) (string, error) {
	u, err := ss.byEmailReader.ReadSensitiveByEmail(email)
	if err != nil {
		return "", err
	}
	err = ss.passwordVerifier.CompareHashAndPassword(u.HashedPassword, password)
	if err != nil {
		return "", err
	}
	return u.ID, nil
}

func (ss Service) Read(id string) (*domain.User, error) {
	user, err := ss.byIDReader.ReadByID(id)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (ss Service) Update(user *domain.User) (*domain.User, error) {
	user, err := ss.updater.Update(user)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (ss Service) Delete(id string) error {
	return ss.deleter.Delete(id)
}
