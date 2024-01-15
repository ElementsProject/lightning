package internal

import "io"

// EOFReader always returns the `io.EOF` error, indicating that the
// reader is empty. This is helpful for the jsonrpc2 connection that
// tries to read from a non-existing `io.Reader`.
type EOFReader struct{}

// Read implements the io.ReadCloser interface.
func (EOFReader) Read(p []byte) (n int, err error) {
	return 0, io.EOF
}

// Close implements the io.ReadCloser interface.
func (EOFReader) Close() error {
	return nil
}
