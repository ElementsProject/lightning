package plugin

import (
	"bytes"
	"context"
	"log"

	"github.com/sourcegraph/jsonrpc2"
)

// LogLevel are the log levels that are supported by core-lightning.
type LogLevel string

const (
	LEVEL_ERROR LogLevel = "error"
	LEVEL_WARN  LogLevel = "warn"
	LEVEL_DEBUG LogLevel = "debug"
	LEVEL_INFO  LogLevel = "info"
)

type logWriter struct {
	conn  *jsonrpc2.Conn
	level LogLevel
}

// Write implements io.Writer
func (w *logWriter) Write(p []byte) (n int, err error) {
	p = bytes.TrimSuffix(p, []byte("\n"))
	err = w.conn.Notify(context.Background(), "log", logEntry{
		Level:   string(w.level),
		Message: string(p),
	})
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

type logEntry struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// NewLogger returns a logger that logs to core-lightning rpc. These logs will
// be printed in the core-lightning logs.
func NewLogger(conn *jsonrpc2.Conn, level LogLevel) *log.Logger {
	return log.New(&logWriter{conn: conn, level: level}, "", 0)
}

// InitDefaultLogger initializes the core `log` logger to pass the logs to the
// core-lightning logger.
func InitDefaultLogger(conn *jsonrpc2.Conn, level LogLevel) {
	log.SetFlags(0)
	log.SetOutput(&logWriter{conn: conn, level: level})
}
