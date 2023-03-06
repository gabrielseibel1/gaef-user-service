package store

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/gabrielseibel1/gaef-user-service/domain"
)

type Store interface {
	Create(user *domain.UserWithHashedPassword) (string, error)
	ReadByID(id string) (*domain.User, error)
	ReadSensitiveByEmail(email string) (*domain.UserWithHashedPassword, error)
	Update(user *domain.User) (*domain.User, error)
	Delete(id string) error
}

type mapStore map[string]*domain.UserWithHashedPassword

var id = 0

func New() Store {
	return &mapStore{}
}

func (ms *mapStore) Create(user *domain.UserWithHashedPassword) (string, error) {
	for _, v := range *ms {
		if v.Email == user.Email {
			return "", errors.New("user exists")
		}
	}
	id++
	createdID := strconv.Itoa(id)
	user.ID = createdID
	(*ms)[createdID] = user
	return createdID, nil
}

func (ms mapStore) ReadByID(id string) (*domain.User, error) {
	u, ok := ms[id]
	if !ok {
		return nil, errors.New("no such user")
	}
	return &u.User, nil
}

func (ms mapStore) ReadSensitiveByEmail(email string) (*domain.UserWithHashedPassword, error) {
	for _, v := range ms {
		if v.Email == email {
			return v, nil
		}
	}
	return nil, fmt.Errorf("no user with email %s", email)
}

func (ms *mapStore) Update(user *domain.User) (*domain.User, error) {
	u, ok := (*ms)[user.ID]
	if !ok {
		return nil, errors.New("no such user")
	}

	for _, v := range *ms {
		if v.Email == user.Email {
			return nil, errors.New("email is taken")
		}
	}

	u.User = *user
	(*ms)[user.ID] = u
	return user, nil
}

func (ms *mapStore) Delete(id string) error {
	delete(*ms, id)
	return nil
}
