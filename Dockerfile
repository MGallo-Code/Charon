# Stage 1 -- Building Go bin

FROM golang:1.25-alpine AS build

WORKDIR /src

# Copy dep files, install required deps
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
RUN go build -o /bin/charon main.go

# Stage 2 -- Runtime image gen
FROM alpine:3.21

# wget needed for charon compose healthcheck
RUN apk add --no-cache wget tzdata
ENV TZ=UTC

COPY --from=build /bin/charon /bin/charon

ENTRYPOINT ["/bin/charon"]
