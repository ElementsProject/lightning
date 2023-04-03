package rpc

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/elementsproject/lightning/contrib/goln/internal"
	"github.com/sourcegraph/jsonrpc2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordHandler struct {
	mutex  sync.Mutex
	called int32
	params []byte
}

func (r *recordHandler) Handler(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) {
	r.mutex.Lock()
	r.called++
	r.params = *req.Params
	r.mutex.Unlock()
	_ = conn.Reply(ctx, req.ID, nil)
}

func TestServer(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	socket := filepath.Join(dir, "test.socket")

	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("error listening to socket: %s", err)
	}
	defer lis.Close()

	rh := &recordHandler{}

	// Create server.
	server := NewServer(context.Background())
	server.RegisterHandler("record", rh.Handler)
	go server.Accept(lis)

	// Call `record` method.
	c, err := net.Dial("unix", socket)
	require.NoError(t, err)
	conn := jsonrpc2.NewConn(context.Background(), jsonrpc2.NewBufferedStream(c, internal.DoubleNewLineCodec{}), nil)

	testParams := struct {
		F1 string `json:"f1"`
		F2 int32  `json:"f2"`
	}{
		F1: "foo",
		F2: 42,
	}
	err = conn.Call(context.Background(), "record", testParams, nil)
	require.NoError(t, err)

	b, err := json.Marshal(testParams)
	require.NoError(t, err)

	assert.EqualValues(t, b, rh.params)
}

func TestServerStop(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	socket := filepath.Join(dir, "test.socket")

	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("error listening to socket: %s", err)
	}
	defer lis.Close()

	rh := &recordHandler{called: 0}

	// Create server.
	server := NewServer(context.Background())
	server.RegisterHandler("record", rh.Handler)
	go server.Accept(lis)

	// Create client.
	c, err := net.Dial("unix", socket)
	require.NoError(t, err)
	conn := jsonrpc2.NewConn(context.Background(), jsonrpc2.NewBufferedStream(c, internal.DoubleNewLineCodec{}), nil)

	// Stop server and call `record` method.
	assert.False(t, server.isStopped())
	server.Stop()
	assert.True(t, server.isStopped())

	err = conn.Call(context.Background(), "record", "foo", nil)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "jsonrpc2: code -32000 message: Server is stopped")
	assert.Equal(t, int32(0), rh.called)
}
