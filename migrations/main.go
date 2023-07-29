package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/grachmannico95/skel/internal/config"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		panic("failed to read environment variable")
	}
	resourcesPath := os.Getenv("RESOURCES_PATH")
	cfgName := os.Getenv("CONFIG_FILE_NAME")
	appConfig := config.NewAppConfig(resourcesPath, cfgName)

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		appConfig.Db.Mysql.Username,
		appConfig.Db.Mysql.Password,
		appConfig.Db.Mysql.Host,
		appConfig.Db.Mysql.Port,
		appConfig.Db.Mysql.Name,
	)

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		panic(err)
	}

	driver, err := mysql.WithInstance(db, &mysql.Config{})
	if err != nil {
		panic(err)
	}

	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		"mysql",
		driver,
	)
	if err != nil {
		panic(err)
	}

	err = m.Up()
	if err != nil {
		panic(err)
	}

	log.Println("migration successful")
}
