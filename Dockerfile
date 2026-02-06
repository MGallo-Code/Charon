# Charon - Multi-stage build
# Stage 1: Build the Go binary
# Stage 2: Copy into minimal image (scratch or distroless)
#
# Usage:
#   docker build -t charon .
#   docker run -e DATABASE_URL=... -e REDIS_URL=... charon
#
# In a monorepo docker-compose, reference this image:
#   services:
#     charon:
#       build: ./path/to/charon
#       environment:
#         DATABASE_URL: postgres://...
#         REDIS_URL: redis://...
