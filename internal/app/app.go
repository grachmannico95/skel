package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/grachmannico95/skel/internal/config"
	"github.com/grachmannico95/skel/internal/domain/auth"
	"github.com/grachmannico95/skel/internal/domain/user"
	"github.com/grachmannico95/skel/internal/runtime/httpserver"
	"github.com/grachmannico95/skel/pkg/crypt"
	"github.com/grachmannico95/skel/pkg/logger"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var ctxLog = context.Background()

func Run() {
	// load environment variable
	err := godotenv.Load()
	if err != nil {
		logger.Fatal(ctxLog, "failed to read environment variable")
	}

	// setup config
	resourcesPath := os.Getenv("RESOURCES_PATH")
	cfgName := os.Getenv("CONFIG_FILE_NAME")
	appConfig := config.NewAppConfig(resourcesPath, cfgName)
	appDictionary := config.NewDictionary(resourcesPath)

	// setup logger
	logger.SetSeverityLevel(appConfig.Log.SeverityLevel)
	logger.Info(ctxLog, "service started")

	// setup database
	db := newDatabaseMysql(appConfig)
	cacheDb := newDatabaseRedis(appConfig)

	// setup repo
	repo := newRepos(repoDependencies{
		db:      db,
		cacheDB: cacheDb,
	})

	// setup service
	service := newServices(serviceDependencies{
		repos:     repo,
		appConfig: appConfig,
	})

	// setup handler
	handler := httpserver.HttpServerHandler{
		AuthService: service.authSvc,
		UserService: service.userSvc,

		Dictionary: appDictionary,
	}
	serverRuntime, err := httpserver.NewHttpServerEcho(appConfig.App.Port, handler)
	if err != nil {
		logger.Fatal(ctxLog, "failed to starting http server runtime cause %v", err)
	}

	// setup interrupt signal
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	logger.Info(ctxLog, "starting http server...")
	// starting runtime
	go func() {
		if err := serverRuntime.Run(); err != nil && err != http.ErrServerClosed {
			logger.Error(ctxLog, "error while starting http server cause %v", err)
		}
	}()

	// setup graceful shutdown
	<-done
	ctx, cancel := context.WithTimeout(ctxLog, 5*time.Second)
	defer func() {
		cancel()
	}()

	// stopping runtime
	logger.Info(ctxLog, "stopping http server...")
	if err := serverRuntime.Stop(ctx); err != nil {
		logger.Fatal(ctxLog, "failed to stopping http server runtime cause %v", err)
	}
	logger.Info(ctxLog, "service stopped")
}

// *** setup databases

func newDatabaseMysql(appConfig config.AppConfig) *gorm.DB {
	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		appConfig.Db.Mysql.Username,
		appConfig.Db.Mysql.Password,
		appConfig.Db.Mysql.Host,
		appConfig.Db.Mysql.Port,
		appConfig.Db.Mysql.Name,
	)

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		logger.Fatal(ctxLog, "failed to create connection to database cause %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		logger.Fatal(ctxLog, "failed to instantiate database cause %v", err)
	}

	sqlDB.SetMaxIdleConns(appConfig.Db.Mysql.Connection.MaxIdle)
	sqlDB.SetMaxOpenConns(appConfig.Db.Mysql.Connection.MaxOpen)
	sqlDB.SetConnMaxLifetime(appConfig.Db.Mysql.Connection.MaxLifetime)

	return db
}

func newDatabaseRedis(appConfig config.AppConfig) *redis.Client {
	db := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", appConfig.Db.Redis.Host, appConfig.Db.Redis.Port),
		Password: appConfig.Db.Redis.Password,
		DB:       appConfig.Db.Redis.DbNum,
	})

	ctx := context.Background()
	err := db.Ping(ctx).Err()
	if err != nil {
		logger.Fatal(ctxLog, "failed to create connection to redis cause %v", err)
	}

	return db
}

// *** setup repositories

type repoDependencies struct {
	db      *gorm.DB
	cacheDB *redis.Client
}

type repos struct {
	authRepo auth.AuthRepo
	userRepo user.UserRepo
}

func newRepos(in repoDependencies) repos {
	// return repos
	return repos{
		authRepo: auth.NewRepoRedis(in.cacheDB),
		userRepo: user.NewRepoMysql(in.db),
	}
}

// *** setup services

type serviceDependencies struct {
	repos     repos
	appConfig config.AppConfig
}

type services struct {
	authSvc auth.AuthService
	userSvc user.UserService
}

func newServices(in serviceDependencies) services {
	// vars
	authCfg := auth.Config{
		AccessToken: auth.AccessTokenConfig{
			Name:   in.appConfig.Constants.AccessTokenName,
			TTL:    in.appConfig.Constants.AccessTokenTTL,
			Secret: in.appConfig.Constants.AccessTokenSecret,
		},
		RefreshToken: auth.RefreshTokenConfig{
			Name:   in.appConfig.Constants.RefreshTokenName,
			TTL:    in.appConfig.Constants.RefreshTokenTTL,
			Secret: in.appConfig.Constants.RefreshTokenSecret,
		},
	}
	crypt := crypt.NewCrypt()

	// auth service
	tokenMaker := auth.NewJwtMaker(jwt.SigningMethodHS256)
	authSvc, err := auth.NewService(in.repos.authRepo, tokenMaker, authCfg)
	if err != nil {
		logger.Fatal(ctxLog, "failed to instantiate auth service cause %v", err)
	}

	// user service
	userSvc := user.NewService(in.repos.userRepo, crypt)

	// return services
	return services{
		authSvc: authSvc,
		userSvc: userSvc,
	}
}
