.PHONY: build
build:
	cd cmd && go build -o ../bin/ssl-verifier

.PHONY: run-single
run-single:
	./bin/ssl-verifier -url ${url}

.PHONY: run-batch
run-batch:
	./bin/ssl-verifier -input ${input} -output ${output}

.PHONY: build-docker
build-docker:
	docker build . -t ssl-verifier:latest

.PHONY: test
test:
	go test ./...
