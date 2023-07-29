FROM golang:1.19.9-alpine as builder
RUN apk update && apk add --no-cache git
WORKDIR /app
COPY go.mod ./
RUN go mod download
RUN go mod tidy
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o migrate migrations/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/.env .
COPY --from=builder /app/main .
COPY --from=builder /app/migrate .
COPY --from=builder /app/resources ./resources
COPY --from=builder /app/migrations ./migrations
EXPOSE 8000
CMD ["./main"]
