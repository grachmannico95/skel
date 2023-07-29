run:
	go run main.go
.PHONY: run

build:
	go build -o dist/main .

watch:
	~/bin/air -c .air.toml
.PHONY: watch

migrate:
	go run migrations/main.go
.PHONY: migrate

test:
	go test ./internal/domain/... -coverprofile=coverage.out.tmp && \
	cat coverage.out.tmp \
	| grep -v "entity" \
	| grep -v "repo_" \
	| grep -v "_mock" \
	> coverage.out && \
	rm coverage.out.tmp
.PHONY: test

test-coverage:
	make test && \
	go tool cover -html=coverage.out
.PHONY: test-coverage

test-percentage:
	make test && \
	clear && \
	go tool cover -func coverage.out | fgrep total | awk '{print $$3}'
.PHONY: test-percentage

compose-up:
	docker-compose up -d
.PHONY: compose-up

compose-migrate:
	docker exec -it skel_ws ./migrate
.PHONY: compose-migrate

compose-down:
	docker-compose down --remove-orphans
.PHONY: compose-down
