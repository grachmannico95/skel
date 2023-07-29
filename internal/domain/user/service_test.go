package user_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/grachmannico95/skel/internal/domain/user"
	"github.com/grachmannico95/skel/pkg/crypt"
	"github.com/stretchr/testify/assert"
)

func TestUserGetByIdentifier(t *testing.T) {
	// prepare args
	type mockArgs struct {
		ctx context.Context
		in  user.InputUserIdentifier
		out user.User
		err error
	}

	// prepare mock
	repoMock := func(args mockArgs) user.UserRepo {
		mock := new(user.UserRepoMock)
		mock.On("Find", args.ctx, args.in).Return(args.out, args.err)
		return mock
	}

	// prepare value
	value := struct {
		ctx      context.Context
		id       string
		username string
	}{
		ctx:      context.Background(),
		id:       "1",
		username: "user 1",
	}

	// prepare test cases
	testCases := []struct {
		name    string
		args    mockArgs
		want    user.User
		wantErr error
	}{
		{
			name: "user found",
			args: mockArgs{
				ctx: value.ctx,
				in: user.InputUserIdentifier{
					ID:       value.id,
					Username: value.username,
				},
				out: user.User{
					ID:       value.id,
					Username: value.username,
				},
			},
			want: user.User{
				ID:       value.id,
				Username: value.username,
			},
		},
		{
			name: "user not found",
			args: mockArgs{
				ctx: value.ctx,
				in: user.InputUserIdentifier{
					ID:       value.id,
					Username: value.username,
				},
				out: user.User{},
				err: user.ErrNotFound,
			},
			want:    user.User{},
			wantErr: user.ErrNotFound,
		},
	}

	// perform unit test
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// arrange
			svc := user.NewService(repoMock(tc.args), crypt.NewCrypt())

			// act
			got, err := svc.GetByIdentifier(value.ctx, tc.args.in)

			// assert
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantErr, err)
		})
	}
}

func TestGetByCredential(t *testing.T) {
	// prepare args
	type argsFind struct {
		ctx context.Context
		in  user.InputUserIdentifier
		out user.User
		err error
	}
	type argsCrypt struct {
		password       string
		hashedPassword string
		err            error
	}
	type mockArgs struct {
		find  argsFind
		crypt argsCrypt
	}

	// prepare mock
	repoMock := func(args mockArgs) user.UserRepo {
		mock := new(user.UserRepoMock)
		mock.On("Find", args.find.ctx, args.find.in).Return(args.find.out, args.find.err)
		return mock
	}
	cryptMock := func(args mockArgs) crypt.Crypt {
		mock := new(crypt.CryptMock)
		mock.On("CompareHashedPassword", args.crypt.hashedPassword, args.crypt.password).Return(args.crypt.err)
		return mock
	}

	// prepare value
	value := struct {
		ctx               context.Context
		username          string
		password          string
		incorrectPassword string
	}{
		ctx:               context.Background(),
		username:          "user 1",
		password:          "user 1 pwd",
		incorrectPassword: "incorrect password",
	}

	// prepare test cases
	testCases := []struct {
		name    string
		args    mockArgs
		want    user.User
		wantErr error
	}{
		{
			name: "user found",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						Username: value.username,
					},
					out: user.User{
						Username: value.username,
						Password: value.password,
					},
				},
				crypt: argsCrypt{
					password:       value.password,
					hashedPassword: value.password,
				},
			},
			want: user.User{
				Username: value.username,
				Password: value.password,
			},
		},
		{
			name: "validation failed",
			args: mockArgs{
				find:  argsFind{},
				crypt: argsCrypt{},
			},
			want:    user.User{},
			wantErr: user.ErrValidation,
		},
		{
			name: "user not found",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						Username: value.username,
					},
					out: user.User{},
					err: user.ErrNotFound,
				},
				crypt: argsCrypt{
					password:       value.password,
					hashedPassword: value.password,
				},
			},
			want:    user.User{},
			wantErr: user.ErrNotFound,
		},
		{
			name: "user's password not match",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						Username: value.username,
					},
					out: user.User{
						Username: value.username,
						Password: value.password,
					},
				},
				crypt: argsCrypt{
					password:       value.incorrectPassword,
					hashedPassword: value.password,
					err:            user.ErrPasswordNotMatch,
				},
			},
			want: user.User{
				Username: value.username,
				Password: value.password,
			},
			wantErr: user.ErrPasswordNotMatch,
		},
	}

	// perform unit test
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// arrange
			svc := user.NewService(repoMock(tc.args), cryptMock(tc.args))

			// act
			got, err := svc.GetByCredential(value.ctx, user.InputUserCredential{
				Username: tc.args.find.in.Username,
				Password: tc.args.crypt.password,
			})

			// assert
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantErr, err)
		})
	}
}

func TestCreate(t *testing.T) {
	// prepare args
	type argsFind struct {
		ctx context.Context
		in  user.InputUserIdentifier
		out user.User
		err error
	}
	type argsInsert struct {
		ctx context.Context
		in  user.InputCreateUser
		out user.User
		err error
	}
	type argsCrypt struct {
		password       string
		hashedPassword string
		err            error
	}
	type mockArgs struct {
		find   argsFind
		insert argsInsert
		crypt  argsCrypt
	}

	// prepare mock
	repoMock := func(args mockArgs) user.UserRepo {
		mock := new(user.UserRepoMock)
		mock.On("Find", args.find.ctx, args.find.in).Return(args.find.out, args.find.err)
		mock.On("Insert", args.insert.ctx, args.insert.in).Return(args.insert.out, args.insert.err)
		return mock
	}
	cryptMock := func(args mockArgs) crypt.Crypt {
		mock := new(crypt.CryptMock)
		mock.On("HashPassword", args.crypt.password).Return(args.crypt.hashedPassword, args.crypt.err)
		return mock
	}

	// prepare value
	value := struct {
		ctx      context.Context
		id       string
		username string
		name     string
		password string
		err      error
	}{
		ctx:      context.Background(),
		id:       "1",
		username: "user 1",
		name:     "user 1",
		password: "user 1 pwd",
		err:      errors.New("err"),
	}

	// prepare test cases
	testCases := []struct {
		name    string
		args    mockArgs
		want    user.User
		wantErr error
	}{
		{
			name: "insert success",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						Username: value.username,
					},
					out: user.User{},
					err: user.ErrNotFound,
				},
				insert: argsInsert{
					ctx: value.ctx,
					in: user.InputCreateUser{
						Username: value.username,
						Name:     value.name,
						Password: value.password,
					},
					out: user.User{
						ID:       value.id,
						Username: value.username,
						Name:     value.name,
						Password: value.password,
					},
				},
				crypt: argsCrypt{
					password:       value.password,
					hashedPassword: value.password,
				},
			},
			want: user.User{
				ID:       value.id,
				Username: value.username,
				Name:     value.name,
				Password: value.password,
			},
		},
		{
			name: "validation failed",
			args: mockArgs{
				find:   argsFind{},
				insert: argsInsert{},
				crypt:  argsCrypt{},
			},
			want:    user.User{},
			wantErr: user.ErrValidation,
		},
		{
			name: "error while finding user data",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						Username: value.username,
					},
					out: user.User{},
					err: value.err,
				},
				insert: argsInsert{
					ctx: value.ctx,
					in: user.InputCreateUser{
						Username: value.username,
						Name:     value.name,
						Password: value.password,
					},
					out: user.User{},
				},
				crypt: argsCrypt{},
			},
			want:    user.User{},
			wantErr: value.err,
		},
		{
			name: "username already exist",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						Username: value.username,
					},
					out: user.User{
						Username: value.username,
					},
				},
				insert: argsInsert{
					ctx: value.ctx,
					in: user.InputCreateUser{
						Username: value.username,
						Name:     value.name,
						Password: value.password,
					},
					out: user.User{},
					err: user.ErrUsernameAlreadyUsed,
				},
				crypt: argsCrypt{},
			},
			want:    user.User{},
			wantErr: user.ErrUsernameAlreadyUsed,
		},
		{
			name: "hashing password failed",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						Username: value.username,
					},
					out: user.User{},
					err: user.ErrNotFound,
				},
				insert: argsInsert{
					ctx: value.ctx,
					in: user.InputCreateUser{
						Username: value.username,
						Name:     value.name,
						Password: value.password,
					},
					out: user.User{},
				},
				crypt: argsCrypt{
					password:       value.password,
					hashedPassword: value.password,
					err:            value.err,
				},
			},
			want:    user.User{},
			wantErr: value.err,
		},
	}

	// perform unit test
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// arrange
			svc := user.NewService(repoMock(tc.args), cryptMock(tc.args))

			// act
			got, err := svc.Create(value.ctx, user.InputCreateUser{
				Username: tc.args.insert.in.Username,
				Name:     tc.args.insert.in.Name,
				Password: tc.args.insert.in.Password,
			})

			// assert
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.wantErr, err)
		})
	}
}

func TestChangeUsername(t *testing.T) {
	// prepare args
	type argsFind struct {
		ctx context.Context
		in  user.InputUserIdentifier
		out user.User
		err error
	}
	type argsExist struct {
		ctx context.Context
		in  user.InputUserIdentifier
		out user.User
		err error
	}
	type argsUpdate struct {
		ctx context.Context
		in  user.User
		out user.User
		err error
	}
	type mockArgs struct {
		find   argsFind
		exist  argsExist
		update argsUpdate
	}

	// prepare mock
	repoMock := func(args mockArgs) user.UserRepo {
		mock := new(user.UserRepoMock)
		mock.On("Find", args.find.ctx, args.find.in).Return(args.find.out, args.find.err)
		mock.On("Find", args.exist.ctx, args.exist.in).Return(args.exist.out, args.exist.err)
		mock.On("Update", args.update.ctx, args.update.in).Return(args.update.out, args.update.err)
		return mock
	}

	// prepare value
	value := struct {
		ctx         context.Context
		id          string
		username    string
		newUsername string
		updatedAt   time.Time
		err         error
	}{
		ctx:         context.Background(),
		id:          "1",
		username:    "user 1",
		newUsername: "user 1 updated",
		updatedAt:   time.Now(),
		err:         errors.New("err"),
	}

	// prepare test cases
	testCases := []struct {
		name    string
		args    mockArgs
		want    user.User
		wantErr error
	}{
		{
			name: "update success",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						ID: value.id,
					},
					out: user.User{
						ID:       value.id,
						Username: value.username,
					},
				},
				exist: argsExist{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						Username: value.newUsername,
					},
					out: user.User{},
					err: user.ErrNotFound,
				},
				update: argsUpdate{
					ctx: value.ctx,
					in: user.User{
						ID:       value.id,
						Username: value.newUsername,
					},
					out: user.User{
						ID:       value.id,
						Username: value.newUsername,
					},
				},
			},
			want: user.User{
				ID:       value.id,
				Username: value.newUsername,
			},
		},
		{
			name: "validation failed",
			args: mockArgs{
				find:   argsFind{},
				exist:  argsExist{},
				update: argsUpdate{},
			},
			want:    user.User{},
			wantErr: user.ErrValidation,
		},
		{
			name: "error while finding user data",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						ID: value.id,
					},
					out: user.User{},
					err: value.err,
				},
				exist: argsExist{},
				update: argsUpdate{
					ctx: value.ctx,
					in: user.User{
						ID:       value.id,
						Username: value.newUsername,
					},
					out: user.User{},
				},
			},
			want:    user.User{},
			wantErr: value.err,
		},
		{
			name: "used same username",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						ID: value.id,
					},
					out: user.User{
						ID:       value.id,
						Username: value.username,
					},
				},
				exist: argsExist{},
				update: argsUpdate{
					ctx: value.ctx,
					in: user.User{
						ID:       value.id,
						Username: value.username,
					},
				},
			},
			want: user.User{
				ID:       value.id,
				Username: value.username,
			},
		},
		{
			name: "error while finding duplicate data",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						ID: value.id,
					},
					out: user.User{
						ID:       value.id,
						Username: value.username,
					},
				},
				exist: argsExist{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						Username: value.newUsername,
					},
					out: user.User{},
					err: value.err,
				},
				update: argsUpdate{
					ctx: value.ctx,
					in: user.User{
						ID:       value.id,
						Username: value.newUsername,
					},
				},
			},
			want: user.User{
				ID:       value.id,
				Username: value.username,
			},
			wantErr: value.err,
		},
		{
			name: "username already used",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						ID: value.id,
					},
					out: user.User{
						ID:       value.id,
						Username: value.username,
					},
				},
				exist: argsExist{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						Username: value.newUsername,
					},
					out: user.User{
						ID:       value.id,
						Username: value.newUsername,
					},
				},
				update: argsUpdate{
					ctx: value.ctx,
					in: user.User{
						ID:       value.id,
						Username: value.newUsername,
					},
				},
			},
			want: user.User{
				ID:       value.id,
				Username: value.username,
			},
			wantErr: user.ErrUsernameAlreadyUsed,
		},
	}

	// perform unit test
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// arrange
			svc := user.NewService(repoMock(tc.args), crypt.NewCrypt())

			// act
			got, err := svc.ChangeUsername(value.ctx, user.InputChangeUsername{
				ID:        tc.args.update.in.ID,
				Username:  tc.args.update.in.Username,
				UpdatedAt: &tc.args.find.out.UpdatedAt,
			})

			// assert
			assert.Equal(t, tc.want.Username, got.Username)
			assert.Equal(t, tc.wantErr, err)
		})
	}
}

func TestChangeName(t *testing.T) {
	// prepare args
	type argsFind struct {
		ctx context.Context
		in  user.InputUserIdentifier
		out user.User
		err error
	}
	type argsUpdate struct {
		ctx context.Context
		in  user.User
		out user.User
		err error
	}
	type mockArgs struct {
		find   argsFind
		update argsUpdate
	}

	// prepare mock
	repoMock := func(args mockArgs) user.UserRepo {
		mock := new(user.UserRepoMock)
		mock.On("Find", args.find.ctx, args.find.in).Return(args.find.out, args.find.err)
		mock.On("Update", args.update.ctx, args.update.in).Return(args.update.out, args.update.err)
		return mock
	}

	// prepare value
	value := struct {
		ctx       context.Context
		id        string
		name      string
		newName   string
		updatedAt time.Time
		err       error
	}{
		ctx:       context.Background(),
		id:        "1",
		name:      "user 1",
		newName:   "user 1 updated",
		updatedAt: time.Now(),
		err:       errors.New("err"),
	}

	// prepare test cases
	testCases := []struct {
		name    string
		args    mockArgs
		want    user.User
		wantErr error
	}{
		{
			name: "update success",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						ID: value.id,
					},
					out: user.User{
						ID:   value.id,
						Name: value.name,
					},
				},
				update: argsUpdate{
					ctx: value.ctx,
					in: user.User{
						ID:   value.id,
						Name: value.newName,
					},
					out: user.User{
						ID:   value.id,
						Name: value.newName,
					},
				},
			},
			want: user.User{
				ID:   value.id,
				Name: value.newName,
			},
		},
		{
			name: "validation failed",
			args: mockArgs{
				find:   argsFind{},
				update: argsUpdate{},
			},
			want:    user.User{},
			wantErr: user.ErrValidation,
		},
		{
			name: "error while finding user data",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						ID: value.id,
					},
					out: user.User{},
					err: value.err,
				},
				update: argsUpdate{
					ctx: value.ctx,
					in: user.User{
						ID:   value.id,
						Name: value.newName,
					},
					out: user.User{},
				},
			},
			want:    user.User{},
			wantErr: value.err,
		},
	}

	// perform unit test
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// arrange
			svc := user.NewService(repoMock(tc.args), crypt.NewCrypt())

			// act
			got, err := svc.ChangeName(value.ctx, user.InputChangeName{
				ID:        tc.args.update.in.ID,
				Name:      tc.args.update.in.Name,
				UpdatedAt: &tc.args.find.out.UpdatedAt,
			})

			// assert
			assert.Equal(t, tc.want.Username, got.Username)
			assert.Equal(t, tc.wantErr, err)
		})
	}
}

func TestChangePassword(t *testing.T) {
	// prepare args
	type argsFind struct {
		ctx context.Context
		in  user.InputUserIdentifier
		out user.User
		err error
	}
	type argsCrypt struct {
		oldPassword              string
		oldHashedPassword        string
		newPassword              string
		newHashedPassword        string
		errCompareHashedPassword error
		errHashPassword          error
	}
	type argsUpdate struct {
		ctx context.Context
		in  user.User
		out user.User
		err error
	}
	type mockArgs struct {
		find   argsFind
		crypt  argsCrypt
		update argsUpdate
	}

	// prepare mock
	repoMock := func(args mockArgs) user.UserRepo {
		mock := new(user.UserRepoMock)
		mock.On("Find", args.find.ctx, args.find.in).Return(args.find.out, args.find.err)
		mock.On("Update", args.update.ctx, args.update.in).Return(args.update.out, args.update.err)
		return mock
	}
	cryptMock := func(args mockArgs) crypt.Crypt {
		mock := new(crypt.CryptMock)
		mock.On("CompareHashedPassword", args.crypt.oldHashedPassword, args.crypt.oldPassword).Return(args.crypt.errCompareHashedPassword)
		mock.On("HashPassword", args.crypt.newPassword).Return(args.crypt.newHashedPassword, args.crypt.errHashPassword)
		return mock
	}

	// prepare value
	value := struct {
		ctx         context.Context
		id          string
		oldPassword string
		newPassword string
		updatedAt   time.Time
		err         error
	}{
		ctx:         context.Background(),
		id:          "1",
		oldPassword: "old password",
		newPassword: "new password",
		updatedAt:   time.Now(),
		err:         errors.New("err"),
	}

	// prepare test cases
	testCases := []struct {
		name    string
		args    mockArgs
		want    user.User
		wantErr error
	}{
		{
			name: "update success",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						ID: value.id,
					},
					out: user.User{
						ID:       value.id,
						Password: value.oldPassword,
					},
				},
				crypt: argsCrypt{
					oldPassword:       value.oldPassword,
					oldHashedPassword: value.oldPassword,
					newPassword:       value.newPassword,
					newHashedPassword: value.newPassword,
				},
				update: argsUpdate{
					ctx: value.ctx,
					in: user.User{
						ID:       value.id,
						Password: value.newPassword,
					},
					out: user.User{
						ID:       value.id,
						Password: value.newPassword,
					},
				},
			},
			want: user.User{
				ID:       value.id,
				Password: value.newPassword,
			},
		},
		{
			name: "validation failed",
			args: mockArgs{
				find:   argsFind{},
				update: argsUpdate{},
			},
			want:    user.User{},
			wantErr: user.ErrValidation,
		},
		{
			name: "error while finding user data",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						ID: value.id,
					},
					out: user.User{},
					err: value.err,
				},
				crypt: argsCrypt{
					oldPassword:       value.oldPassword,
					oldHashedPassword: value.oldPassword,
					newPassword:       value.newPassword,
					newHashedPassword: value.newPassword,
				},
				update: argsUpdate{
					ctx: value.ctx,
					in: user.User{
						ID:       value.id,
						Password: value.newPassword,
					},
					out: user.User{},
				},
			},
			want:    user.User{},
			wantErr: value.err,
		},
		{
			name: "user's password not match",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						ID: value.id,
					},
					out: user.User{
						ID:       value.id,
						Password: value.oldPassword,
					},
				},
				crypt: argsCrypt{
					oldPassword:              value.newPassword,
					oldHashedPassword:        value.oldPassword,
					newPassword:              value.newPassword,
					newHashedPassword:        value.newPassword,
					errCompareHashedPassword: user.ErrPasswordNotMatch,
				},
				update: argsUpdate{
					ctx: value.ctx,
					in: user.User{
						ID:       value.id,
						Password: value.newPassword,
					},
					out: user.User{
						ID:       value.id,
						Password: value.newPassword,
					},
				},
			},
			want: user.User{
				ID:       value.id,
				Password: value.newPassword,
			},
			wantErr: user.ErrPasswordNotMatch,
		},
		{
			name: "hashing password failed",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						ID: value.id,
					},
					out: user.User{
						ID:       value.id,
						Password: value.oldPassword,
					},
				},
				crypt: argsCrypt{
					oldPassword:       value.oldPassword,
					oldHashedPassword: value.oldPassword,
					newPassword:       value.newPassword,
					newHashedPassword: value.newPassword,
					errHashPassword:   value.err,
				},
				update: argsUpdate{
					ctx: value.ctx,
					in: user.User{
						ID:       value.id,
						Password: value.newPassword,
					},
					out: user.User{
						ID:       value.id,
						Password: value.newPassword,
					},
				},
			},
			want: user.User{
				ID:       value.id,
				Password: value.newPassword,
			},
			wantErr: value.err,
		},
	}

	// perform unit test
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// arrange
			svc := user.NewService(repoMock(tc.args), cryptMock(tc.args))

			// act
			got, err := svc.ChangePassword(value.ctx, user.InputChangePassword{
				ID:          tc.args.update.in.ID,
				OldPassword: tc.args.crypt.oldPassword,
				NewPassword: tc.args.crypt.newPassword,
				UpdatedAt:   &tc.args.find.out.UpdatedAt,
			})

			// assert
			assert.Equal(t, tc.want.Username, got.Username)
			assert.Equal(t, tc.wantErr, err)
		})
	}
}

func TestDeactivate(t *testing.T) {
	// prepare args
	type argsFind struct {
		ctx context.Context
		in  user.InputUserIdentifier
		out user.User
		err error
	}
	type argsUpdate struct {
		ctx context.Context
		in  user.User
		out user.User
		err error
	}
	type mockArgs struct {
		find   argsFind
		update argsUpdate
	}

	// prepare mock
	repoMock := func(args mockArgs) user.UserRepo {
		mock := new(user.UserRepoMock)
		mock.On("Find", args.find.ctx, args.find.in).Return(args.find.out, args.find.err)
		mock.On("Update", args.update.ctx, args.update.in).Return(args.update.out, args.update.err)
		return mock
	}

	// prepare value
	value := struct {
		ctx       context.Context
		id        string
		deleted   int8
		updatedAt time.Time
		err       error
	}{
		ctx:       context.Background(),
		id:        "1",
		deleted:   1,
		updatedAt: time.Now(),
		err:       errors.New("err"),
	}

	// prepare test cases
	testCases := []struct {
		name    string
		args    mockArgs
		want    user.User
		wantErr error
	}{
		{
			name: "deactivate success",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						ID: value.id,
					},
					out: user.User{
						ID: value.id,
					},
				},
				update: argsUpdate{
					ctx: value.ctx,
					in: user.User{
						ID:      value.id,
						Deleted: value.deleted,
					},
					out: user.User{
						ID:      value.id,
						Deleted: value.deleted,
					},
				},
			},
			want: user.User{
				ID:      value.id,
				Deleted: value.deleted,
			},
		},
		{
			name: "validation failed",
			args: mockArgs{
				find:   argsFind{},
				update: argsUpdate{},
			},
			want:    user.User{},
			wantErr: user.ErrValidation,
		},
		{
			name: "error while finding user data",
			args: mockArgs{
				find: argsFind{
					ctx: value.ctx,
					in: user.InputUserIdentifier{
						ID: value.id,
					},
					out: user.User{},
					err: value.err,
				},
				update: argsUpdate{
					ctx: value.ctx,
					in: user.User{
						ID:      value.id,
						Deleted: value.deleted,
					},
					out: user.User{},
				},
			},
			want:    user.User{},
			wantErr: value.err,
		},
	}

	// perform unit test
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// arrange
			svc := user.NewService(repoMock(tc.args), crypt.NewCrypt())

			// act
			got, err := svc.Deactivate(value.ctx, user.InputDeactivate{
				ID:        tc.args.update.in.ID,
				UpdatedAt: &tc.args.find.out.UpdatedAt,
			})

			// assert
			assert.Equal(t, tc.want.Username, got.Username)
			assert.Equal(t, tc.wantErr, err)
		})
	}
}
