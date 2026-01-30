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
VOLUME ["/data"]
ENV DB_PATH=/data/forum.db

# <<< ADD THIS LINE
EXPOSE 8080

CMD ["./forum"]
