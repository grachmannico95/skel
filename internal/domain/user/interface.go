package user

import "context"

type (
	//go:generate mockery --dir internal/domain/user --inpackage --name UserRepo --structname UserRepoMock --outpkg=user --output=internal/domain/user --filename=repo_mock.go
	UserRepo interface {
		Find(ctx context.Context, in InputUserIdentifier) (user User, err error)
		Insert(ctx context.Context, in InputCreateUser) (user User, err error)
		Update(ctx context.Context, in User) (user User, err error)
	}

	UserService interface {
		GetByIdentifier(ctx context.Context, in InputUserIdentifier) (user User, err error)
		GetByCredential(ctx context.Context, in InputUserCredential) (user User, err error)
		Create(ctx context.Context, in InputCreateUser) (user User, err error)
		ChangeUsername(ctx context.Context, in InputChangeUsername) (user User, err error)
		ChangeName(ctx context.Context, in InputChangeName) (user User, err error)
		ChangePassword(ctx context.Context, in InputChangePassword) (user User, err error)
		Deactivate(ctx context.Context, in InputDeactivate) (user User, err error)
	}
)
