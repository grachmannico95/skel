package user

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type UserMysql struct {
	ID        string    `gorm:"primaryKey;column:id"`
	Username  string    `gorm:"column:username"`
	Name      string    `gorm:"column:name"`
	Password  string    `gorm:"column:password"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
	Deleted   int8      `gorm:"column:deleted"`
}

func (UserMysql) TableName() string {
	return "users"
}

// ***

type repoMysql struct {
	db *gorm.DB
}

func NewRepoMysql(db *gorm.DB) UserRepo {
	return &repoMysql{
		db: db,
	}
}

// Find: find user data by user's identifier
//
// all input are mandatory
func (r *repoMysql) Find(ctx context.Context, in InputUserIdentifier) (user User, err error) {
	var userMysql UserMysql

	db := r.db.WithContext(ctx).Model(&UserMysql{})
	db = r.filter(db, in)
	err = db.First(&userMysql).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = ErrNotFound
			return
		}
		return
	}

	user = User(userMysql)
	return
}

// filter: filtering selected data
func (r *repoMysql) filter(db *gorm.DB, in InputUserIdentifier) *gorm.DB {
	if in.ID != "" {
		db = db.Where("id = ?", in.ID)
	}
	if in.Username != "" {
		db = db.Where("username = ?", in.Username)
	}

	db = db.Where("deleted = ?", in.Deleted)

	return db
}

// Insert: insert user's data
//
// all input are mandatory
func (r *repoMysql) Insert(ctx context.Context, in InputCreateUser) (user User, err error) {
	data := UserMysql{
		ID:        uuid.New().String(),
		Username:  in.Username,
		Name:      in.Name,
		Password:  in.Password,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Deleted:   0,
	}
	err = r.db.WithContext(ctx).Model(&UserMysql{}).Create(data).Error
	if err != nil {
		return
	}

	user = User(data)
	return
}

// Update: update user's data
//
// user's ID is mandatory
func (r *repoMysql) Update(ctx context.Context, in User) (user User, err error) {
	userMysql := UserMysql(in)

	err = r.db.WithContext(ctx).Model(&UserMysql{}).
		Where("id = ?", in.ID).
		Updates(&userMysql).
		Error
	if err != nil {
		return
	}

	user = in
	return
}
