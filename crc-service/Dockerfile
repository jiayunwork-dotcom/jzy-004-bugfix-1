# syntax=docker/dockerfile:1

# Build stage: run the full test suite, then compile a static binary.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN go vet ./... \
    && go test ./... \
    && CGO_ENABLED=0 go build -trimpath -o /out/crcd ./cmd/crcd

# Runtime stage: nothing but the static binary and a non-root user.
FROM alpine:3.20
RUN adduser -D -u 10001 crc
USER crc
COPY --from=build /out/crcd /usr/local/bin/crcd
EXPOSE 8080
ENV PORT=8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD wget -qO- http://127.0.0.1:8080/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/crcd"]
