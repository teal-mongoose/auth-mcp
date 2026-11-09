# The auth-mcp server's image, for Cloud Run. Built by deploy/deploy-staging.sh from the repo as committed.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/auth-mcp ./cmd/auth-mcp

# No shell or package manager, and not running as root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/auth-mcp /auth-mcp
# Settings come from Cloud Run's environment, not a file.
ENTRYPOINT ["/auth-mcp", "-env-file="]
