# Stage 1: Build the Go binary
FROM golang:1.25-alpine AS build

WORKDIR /src

# Copy dependency files first (cached unless go.mod/go.sum change)
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN go build -o /bin/charon main.go

# Stage 2: Minimal runtime image
FROM alpine:3.21

# wget is needed for the compose healthcheck
RUN apk add --no-cache wget

COPY --from=build /bin/charon /bin/charon

ENTRYPOINT ["/bin/charon"]
