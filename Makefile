default:
	@echo cifuzz

.PHONY: deps
deps:
	go mod download
	go install honnef.co/go/tools/cmd/staticcheck@latest

.PHONY: build
build: build/linux build/windows build/macosx ;

.PHONY: build/linux
build/linux:
	env GOOS=linux GOARCH=amd64 go build -o build/bin/cifuzz_linux

.PHONY: build/windows
build/windows:
	env GOOS=windows GOARCH=amd64 go build -o build/bin/cifuzz_windows.exe

.PHONY: build/macosx
build/macosx:
	env GOOS=darwin GOARCH=amd64 go build -o build/bin/cifuzz_mac

.PHONY: lint
lint:
	staticcheck $$(go list ./...)
	go vet $$(go list ./...)

.PHONY: fmt
fmt:
	go fmt $$(go list ./...)

.PHONY: test
test:
	go test ./...

.PHONY: test/race
test/race:
	go test -race  ./...

.PHONY: test/coverage
test/coverage:
	go test ./... -coverprofile coverage.out
	go tool cover -html coverage.out

