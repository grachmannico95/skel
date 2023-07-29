package auth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

type repo struct {
	db *redis.Client
}

func NewRepoRedis(db *redis.Client) AuthRepo {
	return &repo{
		db: db,
	}
}

// Find: find auth data
func (r *repo) Find(ctx context.Context, key string) (claims Claims, err error) {
	claimsString, err := r.db.Get(ctx, key).Result()
	if err != nil {
		return
	}

	err = json.Unmarshal([]byte(claimsString), &claims)
	if err != nil {
		return
	}

	return
}

// Insert: insert auth data
func (r *repo) Insert(ctx context.Context, key string, claims Claims, duration time.Duration) (err error) {
	byteClaims, err := json.Marshal(claims)
	if err != nil {
		return
	}

	return r.db.Set(ctx, key, string(byteClaims), duration).Err()
}

// Delete: delete auth data
func (r *repo) Delete(ctx context.Context, key string) (err error) {
	return r.db.Del(ctx, key).Err()
}
