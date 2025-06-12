# enclave/Dockerfile
FROM golang:1.22-alpine AS build_env

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the Go application for Linux (no CGO, static binary)
ARG TARGETARCH
RUN GOOS=linux GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -o /main .

# --- Final image for the Enclave ---
FROM scratch

# Set the entrypoint for the enclave immediately
# This tells Docker that /main is the executable that should run when the container starts.
ENTRYPOINT ["/main"]

# Copy the compiled Go binary from the build stage
COPY --from=build_env /main /main
