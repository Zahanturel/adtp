.PHONY: build test test-integration vet fmt cover run deps docker clean

BINARY := adtpd
ifeq ($(OS),Windows_NT)
	BINARY := adtpd.exe
endif

# Build the daemon binary.
build:
	go build -o $(BINARY) ./cmd/adtpd

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
	./$(BINARY) --config config.yaml

deps:
	go mod tidy

docker:
	docker build -t zahanturel/adtpd .

clean:
	go clean
	$(RM) platform.key api.key instance.id
