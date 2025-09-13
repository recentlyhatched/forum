FROM golang:1.24-alpine AS build
RUN apk add --no-cache git build-base
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=1 go build -o forum ./main.go

FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /app/forum /app/forum
COPY templates /app/templates
COPY static /app/static
# Persist DB to a volume (or create empty)
VOLUME ["/data"]
ENV DB_PATH=/data/forum.db
# Use a small wrapper to create db if missing, but our binary auto-creates schema if DB present
CMD ["./forum"]
