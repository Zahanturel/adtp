.PHONY: build test test-integration vet fmt cover run deps docker clean

# Build the daemon binary.
build:
	go build -o adtpd ./cmd/adtpd

# Run the unit test suite (in-memory backend).
test:
	go test ./...

# Run the PostgreSQL integration tests (requires ADTP_TEST_POSTGRES).
test-integration:
	go test -tags integration ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

cover:
	go test -cover ./...

run: build
	./adtpd --config config.yaml

deps:
	go mod tidy

docker:
	docker build -t adtp/adtpd .

clean:
	rm -f adtpd platform.key api.key instance.id
