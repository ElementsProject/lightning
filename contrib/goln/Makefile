GOLN_EXAMPLE_BIN="goln-example"

check-go:
	go test -v ./...

clean-go:
	go clean
	rm -f ${GOLN_EXAMPLE_BIN}

example:
	go build -o ${GOLN_EXAMPLE_BIN} example.go