package service

import (
	"errors"
	"testing"

	"github.com/gabrielseibel1/gaef-user-service/domain"
)

type mockPasswordHasher struct {
	password       string
	hashedPassword string
	err            error
}

func (mph *mockPasswordHasher) GenerateFromPassword(password string) (string, error) {
	mph.password = password
	return mph.hashedPassword, mph.err
}

type mockCreator struct {
	user *domain.UserWithHashedPassword
	id   string
	err  error
}

func (mc *mockCreator) Create(user *domain.UserWithHashedPassword) (string, error) {
	mc.user = user
	return mc.id, mc.err
}

func TestService_Create_OK(t *testing.T) {
	// define mocks and dummies and inject dependencies
	mockPasswordHasher := &mockPasswordHasher{
		hashedPassword: "hashed",
		err:            nil,
	}
	mockCreator := &mockCreator{
		id:  "42",
		err: nil,
	}
	dummyUser := &domain.User{
		Name:  "Gabriel de Souza Seibel",
		Email: "gabriel.seibel@tuta.io",
	}
	dummyPassword := "test123"
	s := Service{
		passwordHasher: mockPasswordHasher,
		creator:        mockCreator,
	}

	// run code under test
	id, err := s.Create(dummyUser, dummyPassword)

	// assert good results and side effects
	if err != nil {
		t.Errorf("Service.Create() error: %v, want %v", err.Error(), mockCreator.err.Error())
	}
	if id != mockCreator.id {
		t.Errorf("Service.Create() = %v, want %v", id, mockCreator.id)
	}
	if mockCreator.user.User != *dummyUser {
		t.Errorf("Service.Create() saved user %v, want %v", mockCreator.user.User, *dummyUser)
	}
	if mockPasswordHasher.password != dummyPassword {
		t.Errorf("Service.Create() hashed password %v, want %v", mockPasswordHasher.password, dummyPassword)
	}
	if mockCreator.user.HashedPassword != mockPasswordHasher.hashedPassword {
		t.Errorf("Service.Create() saved password %v, want %v", mockCreator.user.HashedPassword, mockPasswordHasher.hashedPassword)
	}
}

func TestService_Create_ErrCreator(t *testing.T) {
	// define mocks and dummies and inject dependencies
	mockPasswordHasher := &mockPasswordHasher{
		hashedPassword: "hashed",
		err:            nil,
	}
	mockCreator := &mockCreator{
		id:  "",
		err: errors.New("mock error from creator"),
	}
	dummyUser := &domain.User{
		Name:  "Gabriel de Souza Seibel",
		Email: "gabriel.seibel@tuta.io",
	}
	dummyPassword := "test123"
	s := Service{
		passwordHasher: mockPasswordHasher,
		creator:        mockCreator,
	}

	// run code under test
	id, err := s.Create(dummyUser, dummyPassword)

	// assert good results and side effects
	if err == nil {
		t.Errorf("Service.Create() error: nil, want %v", mockCreator.err.Error())
	}
	if id != mockCreator.id {
		t.Errorf("Service.Create() = %v, want %v", id, mockCreator.id)
	}
	if mockCreator.user.User != *dummyUser {
		t.Errorf("Service.Create() saved user %v, want %v", mockCreator.user.User, *dummyUser)
	}
	if mockPasswordHasher.password != dummyPassword {
		t.Errorf("Service.Create() hashed password %v, want %v", mockPasswordHasher.password, dummyPassword)
	}
	if mockCreator.user.HashedPassword != mockPasswordHasher.hashedPassword {
		t.Errorf("Service.Create() saved password %v, want %v", mockCreator.user.HashedPassword, mockPasswordHasher.hashedPassword)
	}
}

func TestService_Create_ErrHasher(t *testing.T) {
	// define mocks and dummies and inject dependencies
	mockPasswordHasher := &mockPasswordHasher{
		hashedPassword: "hashed",
		err:            errors.New("mock error from hasher"),
	}
	mockCreator := &mockCreator{
		id:  "42",
		err: nil,
	}
	dummyUser := &domain.User{
		Name:  "Gabriel de Souza Seibel",
		Email: "gabriel.seibel@tuta.io",
	}
	dummyPassword := "test123"
	s := Service{
		passwordHasher: mockPasswordHasher,
		creator:        mockCreator,
	}

	// run code under test
	id, err := s.Create(dummyUser, dummyPassword)

	// assert good results and side effects
	if err == nil {
		t.Errorf("Service.Create() error: nil, want %v", mockPasswordHasher.err.Error())
	}
	if id != "" {
		t.Errorf("Service.Create() = %v, want ", id)
	}
	if mockCreator.user != nil {
		t.Errorf("Service.Create() saved user %v, want %v", mockCreator.user.User, *dummyUser)
	}
	if mockPasswordHasher.password != dummyPassword {
		t.Errorf("Service.Create() hashed password %v, want %v", mockPasswordHasher.password, dummyPassword)
	}
}

type mockByEmailReader struct {
	email string
	user  *domain.UserWithHashedPassword
	err   error
}

func (m *mockByEmailReader) ReadSensitiveByEmail(email string) (*domain.UserWithHashedPassword, error) {
	m.email = email
	return m.user, m.err
}

type mockPasswordVerifier struct {
	hashedPassword string
	password       string
	err            error
}

func (m *mockPasswordVerifier) CompareHashAndPassword(hashedPassword string, password string) error {
	m.hashedPassword = hashedPassword
	m.password = password
	return m.err
}

func TestService_Login_OK(t *testing.T) {
	// prepare and inject dependencies
	dummyEmail := "gabrielseibel1@gmail.com"
	dummyPassword := "test123"
	mockReader := &mockByEmailReader{
		user: &domain.UserWithHashedPassword{
			User: domain.User{
				ID:    "42",
				Name:  "Gabriel de Souza Seibel",
				Email: "gabriel.seibel@tuta.io",
			},
			HashedPassword: "hashed",
		},
		err: nil,
	}
	mockPasswordVerifier := &mockPasswordVerifier{
		err: nil,
	}
	s := Service{
		byEmailReader:    mockReader,
		passwordVerifier: mockPasswordVerifier,
	}

	// run code under test
	id, err := s.Login(dummyEmail, dummyPassword)

	// assert good results and side-effects
	if err != nil {
		t.Errorf("Service.Login() error: %v, want nil", err.Error())
	}
	if id != mockReader.user.ID {
		t.Errorf("Service.Login() = id: %v, want %v", id, mockReader.user.ID)
	}
	if mockReader.email != dummyEmail {
		t.Errorf("Service.Login() read email: %v, want %v", mockReader.email, dummyEmail)
	}
	if mockPasswordVerifier.hashedPassword != mockReader.user.HashedPassword {
		t.Errorf("Service.Login() compared hashed password: %v, want %v", mockPasswordVerifier.hashedPassword, mockReader.user.HashedPassword)
	}
	if mockPasswordVerifier.password != dummyPassword {
		t.Errorf("Service.Login() compared password: %v, want %v", mockPasswordVerifier.password, dummyPassword)
	}
}

func TestService_Login_ErrReader(t *testing.T) {
	// prepare and inject dependencies
	dummyEmail := "gabrielseibel1@gmail.com"
	dummyPassword := "test123"
	mockReader := &mockByEmailReader{
		user: &domain.UserWithHashedPassword{
			User: domain.User{
				ID:    "42",
				Name:  "Gabriel de Souza Seibel",
				Email: "gabriel.seibel@tuta.io",
			},
			HashedPassword: "hashed",
		},
		err: errors.New("mock error from reader"),
	}
	mockPasswordVerifier := &mockPasswordVerifier{
		err: nil,
	}
	s := Service{
		byEmailReader:    mockReader,
		passwordVerifier: mockPasswordVerifier,
	}

	// run code under test
	id, err := s.Login(dummyEmail, dummyPassword)

	// assert good results and side-effects
	if err == nil {
		t.Errorf("Service.Login() error: nil, want %v", mockReader.err.Error())
	}
	if id != "" {
		t.Errorf("Service.Login() = id: %v, want ", id)
	}
	if mockReader.email != dummyEmail {
		t.Errorf("Service.Login() read email: %v, want %v", mockReader.email, dummyEmail)
	}
	if mockPasswordVerifier.hashedPassword != "" {
		t.Errorf("Service.Login() compared hashed password: %v, want ", mockPasswordVerifier.hashedPassword)
	}
	if mockPasswordVerifier.password != "" {
		t.Errorf("Service.Login() compared password: %v, want ", mockPasswordVerifier.password)
	}
}

func TestService_Login_ErrVerifier(t *testing.T) {
	// prepare and inject dependencies
	dummyEmail := "gabrielseibel1@gmail.com"
	dummyPassword := "test123"
	mockReader := &mockByEmailReader{
		user: &domain.UserWithHashedPassword{
			User: domain.User{
				ID:    "42",
				Name:  "Gabriel de Souza Seibel",
				Email: "gabriel.seibel@tuta.io",
			},
			HashedPassword: "hashed",
		},
		err: nil,
	}
	mockPasswordVerifier := &mockPasswordVerifier{
		err: errors.New("mock error verifier"),
	}
	s := Service{
		byEmailReader:    mockReader,
		passwordVerifier: mockPasswordVerifier,
	}

	// run code under test
	id, err := s.Login(dummyEmail, dummyPassword)

	// assert good results and side-effects
	if err == nil {
		t.Errorf("Service.Login() error: nil, want %v", mockPasswordVerifier.err.Error())
	}
	if id != "" {
		t.Errorf("Service.Login() = id: %v, want ", id)
	}
	if mockReader.email != dummyEmail {
		t.Errorf("Service.Login() read email: %v, want %v", mockReader.email, dummyEmail)
	}
	if mockPasswordVerifier.hashedPassword != mockReader.user.HashedPassword {
		t.Errorf("Service.Login() compared hashed password: %v, want %v", mockPasswordVerifier.hashedPassword, mockReader.user.HashedPassword)
	}
	if mockPasswordVerifier.password != dummyPassword {
		t.Errorf("Service.Login() compared password: %v, want %v", mockPasswordVerifier.password, dummyPassword)
	}
}

type mockByIDReader struct {
	id   string
	user *domain.User
	err  error
}

func (m *mockByIDReader) ReadByID(id string) (*domain.User, error) {
	m.id = id
	return m.user, m.err
}

func TestService_Read_OK(t *testing.T) {
	// prepare and inject dependencies
	dummyID := "87"
	mockReader := &mockByIDReader{
		user: &domain.User{
			ID:    "42",
			Name:  "Gabriel de Souza Seibel",
			Email: "gabriel.seibel@tuta.io",
		},
		err: nil,
	}
	s := &Service{
		byIDReader: mockReader,
	}

	// run code under test
	user, err := s.Read(dummyID)

	// assert good results and side-effects
	if err != nil {
		t.Errorf("Service.Read() = error: %v, want nil", err.Error())
	}
	if user != mockReader.user {
		t.Errorf("Service.Read() = user: %v, want %v", user, mockReader.user)
	}
	if mockReader.id != dummyID {
		t.Errorf("Service.Read() queried id: %v, want %v", mockReader.id, dummyID)
	}
}

func TestService_Read_Err(t *testing.T) {
	// prepare and inject dependencies
	dummyID := "87"
	mockReader := &mockByIDReader{
		user: &domain.User{
			ID:    "42",
			Name:  "Gabriel de Souza Seibel",
			Email: "gabriel.seibel@tuta.io",
		},
		err: errors.New("mock error from reader"),
	}
	s := &Service{
		byIDReader: mockReader,
	}

	// run code under test
	user, err := s.Read(dummyID)

	// assert good results and side-effects
	if err == nil {
		t.Errorf("Service.Read() = error: nil, want %v", mockReader.err.Error())
	}
	if user != nil {
		t.Errorf("Service.Read() = user: %v, want nil", user)
	}
	if mockReader.id != dummyID {
		t.Errorf("Service.Read() queried id: %v, want %v", mockReader.id, dummyID)
	}
}

type mockUpdater struct {
	receiveUser *domain.User
	returnUser  *domain.User
	err         error
}

func (m *mockUpdater) Update(user *domain.User) (*domain.User, error) {
	m.receiveUser = user
	return m.returnUser, m.err
}

func TestService_Update_OK(t *testing.T) {
	// prepare and inject dependencies
	dummyUser := &domain.User{
		ID:    "87",
		Name:  "Gabriel Seibel de Souza",
		Email: "gabrielseibel1@gmail.com",
	}
	mockUpdater := &mockUpdater{
		returnUser: &domain.User{
			ID:    "42",
			Name:  "Gabriel de Souza Seibel",
			Email: "gabriel.seibel@tuta.io",
		},
		err: nil,
	}
	s := &Service{
		updater: mockUpdater,
	}

	// run code under test
	user, err := s.Update(dummyUser)

	// assert good results and side-effects
	if err != nil {
		t.Errorf("Service.Update() = error: %v, want nil", err.Error())
	}
	if user != mockUpdater.returnUser {
		t.Errorf("Service.Update() = user: %v, want %v", user, mockUpdater.returnUser)
	}
	if mockUpdater.receiveUser != dummyUser {
		t.Errorf("Service.Update() updated user: %v, want %v", mockUpdater.receiveUser, dummyUser)
	}
}

func TestService_Update_Err(t *testing.T) {
	// prepare and inject dependencies
	dummyUser := &domain.User{
		ID:    "87",
		Name:  "Gabriel Seibel de Souza",
		Email: "gabrielseibel1@gmail.com",
	}
	mockUpdater := &mockUpdater{
		returnUser: &domain.User{
			ID:    "42",
			Name:  "Gabriel de Souza Seibel",
			Email: "gabriel.seibel@tuta.io",
		},
		err: errors.New("mock error from updater"),
	}
	s := &Service{
		updater: mockUpdater,
	}

	// run code under test
	user, err := s.Update(dummyUser)

	// assert good results and side-effects
	if err == nil {
		t.Errorf("Service.Update() = error: nil, want %v", mockUpdater.err.Error())
	}
	if user != nil {
		t.Errorf("Service.Update() = user: %v, want nil", user)
	}
	if mockUpdater.receiveUser != dummyUser {
		t.Errorf("Service.Update() updated user: %v, want %v", mockUpdater.receiveUser, dummyUser)
	}
}

type mockDeleter struct {
	id  string
	err error
}

func (m *mockDeleter) Delete(id string) error {
	m.id = id
	return m.err
}

func TestService_Delete_OK(t *testing.T) {
	// prepare and inject dependencies
	dummyID := "87"
	mockDeleter := &mockDeleter{
		err: nil,
	}
	s := &Service{
		deleter: mockDeleter,
	}

	// run code under test
	err := s.Delete(dummyID)

	// assert good results and side-effects
	if err != nil {
		t.Errorf("Service.Delete() = error: %v, want nil", err.Error())
	}
	if mockDeleter.id != dummyID {
		t.Errorf("Service.Delete() updated user: %v, want %v", mockDeleter.id, dummyID)
	}
}

func TestService_Delete_Err(t *testing.T) {
	// prepare and inject dependencies
	dummyID := "87"
	mockDeleter := &mockDeleter{
		err: errors.New("mock error from deleter"),
	}
	s := &Service{
		deleter: mockDeleter,
	}

	// run code under test
	err := s.Delete(dummyID)

	// assert good results and side-effects
	if err == nil {
		t.Errorf("Service.Delete() = error: nil, want %v", mockDeleter.err.Error())
	}
	if mockDeleter.id != dummyID {
		t.Errorf("Service.Delete() updated user: %v, want %v", mockDeleter.id, dummyID)
	}
}

func TestNew(t *testing.T) {
	// prepare and inject dependencies
	mockPasswordHasher := &mockPasswordHasher{}
	mockPasswordVerifier := &mockPasswordVerifier{}
	mockCreator := &mockCreator{}
	mockByIDReader := &mockByIDReader{}
	mockByEmailReader := &mockByEmailReader{}
	mockUpdater := &mockUpdater{}
	mockDeleter := &mockDeleter{}

	// run code under test
	s := New(
		mockPasswordHasher,
		mockPasswordVerifier,
		mockCreator,
		mockByIDReader,
		mockByEmailReader,
		mockUpdater,
		mockDeleter,
	)

	// assert good results and side-effects
	if s == nil {
		t.Error("service.New() = nil, want non-nil")
	}
	if s.passwordHasher == nil || s.passwordHasher != mockPasswordHasher {
		t.Error("service.New() did not bind passwordHasher")
	}
	if s.passwordVerifier == nil || s.passwordVerifier != mockPasswordVerifier {
		t.Error("service.New() did not bind passwordVerifier")
	}
	if s.creator == nil || s.creator != mockCreator {
		t.Error("service.New() did not bind creator")
	}
	if s.byIDReader == nil || s.byIDReader != mockByIDReader {
		t.Error("service.New() did not bind byIDReader")
	}
	if s.byEmailReader == nil || s.byEmailReader != mockByEmailReader {
		t.Error("service.New() did not bind byEmailReader")
	}
	if s.updater == nil || s.updater != mockUpdater {
		t.Error("service.New() did not bind updater")
	}
	if s.deleter == nil || s.deleter != mockDeleter {
		t.Error("service.New() did not bind deleter")
	}
}
