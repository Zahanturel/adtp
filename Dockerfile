# Build a static adtpd binary. pgx is pure Go, so CGO is not required.
FROM golang:1.26.4-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
ARG COMMIT=none
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /adtpd ./cmd/adtpd

# Minimal runtime image.
FROM gcr.io/distroless/static-debian12
COPY --from=build /adtpd /adtpd
COPY config.yaml /etc/adtp/config.yaml

# No EXPOSE: the daemon's control plane (credential issuance, delegation,
# revocation) MUST run behind an authenticating gateway / private network for
# production. It binds 127.0.0.1 by default; override with ADTP_SERVER_HOST only
# behind such a gateway, and configure ADTP_SERVER_API_KEYS (or let the daemon
# generate a key on first run, persisted next to the platform key under /data).
# Persist the platform key and generated API key under /data (mount a volume there).
ENV ADTP_IDENTITY_PLATFORM_KEY=/data/platform.key
ENTRYPOINT ["/adtpd", "--config", "/etc/adtp/config.yaml"]
