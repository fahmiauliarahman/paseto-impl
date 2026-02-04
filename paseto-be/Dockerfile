# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
# CGO_ENABLED=0 creates a statically linked binary
RUN CGO_ENABLED=0 GOOS=linux go build -o paseto-app .

# Final stage
FROM alpine:latest

WORKDIR /app

# Install ca-certificates for HTTPS requests if needed (good practice)
RUN apk --no-cache add ca-certificates

# Copy binary from builder
COPY --from=builder /app/paseto-app .

# Expose port
EXPOSE 3001

# Run the application
CMD ["./paseto-app"]
