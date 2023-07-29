package user

import (
	"context"
	"errors"

	"github.com/grachmannico95/skel/pkg/crypt"
	"github.com/grachmannico95/skel/pkg/logger"
	"github.com/grachmannico95/skel/pkg/validator"
)

type service struct {
	userRepo UserRepo
	crypt    crypt.Crypt
}

func NewService(userRepo UserRepo, crypt crypt.Crypt) UserService {
	return &service{
		userRepo: userRepo,
		crypt:    crypt,
	}
}

// GetByIdentifier: get user data by user's identifier
//
// all input are mandatory
func (s *service) GetByIdentifier(ctx context.Context, in InputUserIdentifier) (user User, err error) {
	return s.userRepo.Find(ctx, in)
}

// GetByCredential: get user data by user's credentials
//
// all input are mandatory
func (s *service) GetByCredential(ctx context.Context, in InputUserCredential) (user User, err error) {
	// validate input
	if err = validator.ValidateStruct(in); err != nil {
		logger.Error(ctx, "error while validating input cause %v", err)
		err = ErrValidation
		return
	}

	// get user data by username
	user, err = s.GetByIdentifier(ctx, InputUserIdentifier{
		Username: in.Username,
	})
	if err != nil {
		logger.Error(ctx, "error while getting user data by user cause: %v", err)
		return
	}
	logger.Info(ctx, "success getting user data by id, data: %v", user.toString())

	// compare hashed password and input password
	// err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(in.Password))
	err = s.crypt.CompareHashedPassword(user.Password, in.Password)
	if err != nil {
		logger.Error(ctx, "error while comparing hashed password cause %v", err)
		err = ErrPasswordNotMatch
		return
	}

	return
}

// Create: creating a new user
//
// all input are mandatory
func (s *service) Create(ctx context.Context, in InputCreateUser) (user User, err error) {
	// validate input
	if err = validator.ValidateStruct(in); err != nil {
		logger.Error(ctx, "error while validating input cause %v", err)
		err = ErrValidation
		return
	}

	// check duplicate user's username
	anotherUser, err := s.GetByIdentifier(ctx, InputUserIdentifier{
		Username: in.Username,
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		logger.Error(ctx, "error while checking duplicate user's username cause %v", err)
		return
	}
	logger.Info(ctx, "success checking duplicate user's username, data: %v", anotherUser.toString())

	// check duplicate username
	if anotherUser.Username == in.Username {
		err = ErrUsernameAlreadyUsed
		return
	}

	// hashing user's password
	hashedPassword, err := s.crypt.HashPassword(in.Password)
	if err != nil {
		logger.Error(ctx, "error while hashing user's password cause %v", err)
		return
	}
	in.Password = string(hashedPassword)

	// creating new user
	return s.userRepo.Insert(ctx, in)
}

// ChangeUsername: change user's username by it's ID.
//
// all input are mandatory
func (s *service) ChangeUsername(ctx context.Context, in InputChangeUsername) (user User, err error) {
	// validate input
	if err = validator.ValidateStruct(in); err != nil {
		logger.Error(ctx, "error while validating input cause %v", err)
		err = ErrValidation
		return
	}

	// get user data by id
	user, err = s.GetByIdentifier(ctx, InputUserIdentifier{
		ID: in.ID,
	})
	if err != nil {
		logger.Error(ctx, "error while getting user data by id cause %v", err)
		return
	}
	logger.Info(ctx, "success getting user data by id, data %v", user.toString())

	// return immediately when username is unchanged
	if user.Username == in.Username {
		return
	}

	// check duplicate user's username
	anotherUser, err := s.GetByIdentifier(ctx, InputUserIdentifier{
		Username: in.Username,
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		logger.Error(ctx, "error while checking duplicate user's username cause %v", err)
		return
	}
	logger.Info(ctx, "success checking duplicate user's username, data: %v", anotherUser.toString())

	// check duplicate username
	if anotherUser.Username == in.Username {
		err = ErrUsernameAlreadyUsed
		return
	}

	// apply changes
	user.Username = in.Username
	if in.UpdatedAt != nil {
		user.UpdatedAt = *in.UpdatedAt
	}
	return s.userRepo.Update(ctx, user)
}

// ChangeName: change user's name by it's ID
//
// all input are mandatory
func (s *service) ChangeName(ctx context.Context, in InputChangeName) (user User, err error) {
	// validate input
	if err = validator.ValidateStruct(in); err != nil {
		logger.Error(ctx, "error while validating input cause %v", err)
		err = ErrValidation
		return
	}

	// get user data by id
	user, err = s.GetByIdentifier(ctx, InputUserIdentifier{
		ID: in.ID,
	})
	if err != nil {
		logger.Error(ctx, "error while getting user data by id cause %v", err)
		return
	}
	logger.Info(ctx, "success getting user data by id, data: %v", user.toString())

	// apply changes
	user.Name = in.Name
	if in.UpdatedAt != nil {
		user.UpdatedAt = *in.UpdatedAt
	}
	return s.userRepo.Update(ctx, user)
}

// ChangePassword: change user's password by it's ID
//
// all input are mandatory
func (s *service) ChangePassword(ctx context.Context, in InputChangePassword) (user User, err error) {
	// validate input
	if err = validator.ValidateStruct(in); err != nil {
		logger.Error(ctx, "error while validating input cause %v", err)
		err = ErrValidation
		return
	}

	// get user data by id
	user, err = s.GetByIdentifier(ctx, InputUserIdentifier{
		ID: in.ID,
	})
	if err != nil {
		logger.Error(ctx, "error while getting user data by id cause %v", err)
		return
	}
	logger.Info(ctx, "success getting user data by id, data %v", user.toString())

	// compare hashed password and input old password
	// err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(in.OldPassword))
	err = s.crypt.CompareHashedPassword(user.Password, in.OldPassword)
	if err != nil {
		logger.Error(ctx, "error while comparing hashed password cause %v", err)
		err = ErrPasswordNotMatch
		return
	}

	// hashing user's new password
	// hashedPassword, err := bcrypt.GenerateFromPassword([]byte(in.NewPassword), bcrypt.DefaultCost)
	hashedPassword, err := s.crypt.HashPassword(in.NewPassword)
	if err != nil {
		logger.Error(ctx, "error while hashing password cause %v", err)
		return
	}

	// apply changes
	user.Password = string(hashedPassword)
	if in.UpdatedAt != nil {
		user.UpdatedAt = *in.UpdatedAt
	}
	return s.userRepo.Update(ctx, user)
}

// Deactivate: soft deleting user's data by user's identifier
//
// all input are mandatory
func (s *service) Deactivate(ctx context.Context, in InputDeactivate) (user User, err error) {
	// validate input
	if err = validator.ValidateStruct(in); err != nil {
		logger.Error(ctx, "error while validating input cause %v", err)
		err = ErrValidation
		return
	}

	// get user data by id
	user, err = s.GetByIdentifier(ctx, InputUserIdentifier{
		ID: in.ID,
	})
	if err != nil {
		logger.Error(ctx, "error while getting user data by id cause %v", err)
		return
	}
	logger.Info(ctx, "success getting user data by id, data: %v", user.toString())

	// apply changes
	if in.UpdatedAt != nil {
		user.UpdatedAt = *in.UpdatedAt
	}
	user.Deleted = 1
	return s.userRepo.Update(ctx, user)
}
