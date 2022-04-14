default:
	@echo cifuzz

.PHONY: deps
deps:
	go mod download

.PHONY: deps/dev
deps/dev: deps
	go install honnef.co/go/tools/cmd/staticcheck@latest

.PHONY: build
build: build/linux build/windows build/macosx ;

.PHONY: build/linux
build/linux: deps
	env GOOS=linux GOARCH=amd64 go build -o build/bin/cifuzz_linux

.PHONY: build/windows
build/windows: deps
	env GOOS=windows GOARCH=amd64 go build -o build/bin/cifuzz_windows.exe

.PHONY: build/macosx
build/macosx: deps
	env GOOS=darwin GOARCH=amd64 go build -o build/bin/cifuzz_mac

.PHONY: lint
lint: deps/dev
	staticcheck $$(go list ./...)
	go vet $$(go list ./...)

.PHONY: fmt
fmt:
	go fmt $$(go list ./...)

.PHONY: fmt/check
fmt/check:
	if [ "$$(gofmt -d -l . | wc -l)" -gt 0 ]; then exit 1; fi;

.PHONY: test
test: deps
	go test ./...

.PHONY: test/race
test/race: deps
	go test -race  ./...

.PHONY: test/coverage
test/coverage: deps
	go test ./... -coverprofile coverage.out
	go tool cover -html coverage.out

