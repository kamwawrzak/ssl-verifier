port ?= 8080

.PHONY: build-all
build-all: build-server build-cli

.PHONY: build-cli
build-cli:
	cd cmd/cli && go build -o ../../bin/ssl-verifier

.PHONY: build-server
build-server:
	cd cmd/server && go build -o ../../bin/ssl-verifier-server

.PHONY: run-single
run-single:
	./bin/ssl-verifier -url ${url}

.PHONY: run-batch
run-batch:
	./bin/ssl-verifier -input ${input} -output ${output}

.PHONY: run-server
run-server:
	./bin/ssl-verifier-server -port ${port}

.PHONY: build-docker
build-docker:
	docker build . -t ssl-verifier:latest

.PHONY: test
test:
	go test ./...

.PHONY: test-coverage
test-coverage:
	@mkdir -p tests-results
	@go test -coverprofile=tests-results/coverage.out ./...
	@go tool cover -html=tests-results/coverage.out

.PHONY: lint
lint:
	golangci-lint run
