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

type testParams struct {
	Foo string `json:"foo"`
	Bar int32  `json:"bar"`
}

type echoHandler struct {
	sync.Mutex

	called int32
	ids    []uint64
}

func (t *echoHandler) Handle(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) {
	t.Lock()
	t.called++
	t.ids = append(t.ids, req.ID.Num)
	t.Unlock()

	var res *testParams
	_ = json.Unmarshal(*req.Params, &res)
	_ = conn.Reply(ctx, req.ID, *res)
}

// TestClient_Notify is a simple functional test that checks if a client
// can send a notification.
func TestClient_Notify(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	socket := filepath.Join(dir, "test.socket")
	ctx := context.TODO()

	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer lis.Close()
	done := make(chan struct{})
	buf := make([]byte, 64)
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			conn, err := lis.Accept()
			require.NoError(t, err)
			for {
				_, err := conn.Read(buf)
				if err != nil {
					return
				}
			}
		}
	}()

	client, err := NewClient(ctx, socket)
	require.NoError(t, err)

	// var res *testResponse
	err = client.Notify("foo", testParams{Foo: "foo", Bar: 42})
	require.NoError(t, err)

	// Close the connection to stop the listener routine
	client.conn.Close()
	<-done

	expected := []byte{
		10, 10, 106, 115, 111, 110, 114, 112,
		99, 34, 58, 34, 50, 46, 48, 34,
		44, 34, 109, 101, 116, 104, 111, 100,
		34, 58, 34, 102, 111, 111, 34, 44,
		34, 112, 97, 114, 97, 109, 115, 34,
		58, 123, 34, 102, 111, 111, 34, 58,
		34, 102, 111, 111, 34, 44, 34, 98,
		97, 114, 34, 58, 52, 50, 125, 125,
	}
	assert.Equal(t, expected, buf)
}

// TestClient_Call is a simple functional test that checks if a client
// can `Call` a rpc method.
func TestClient_Call(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	socket := filepath.Join(dir, "test.socket")
	ctx := context.TODO()
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer lis.Close()

	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			codec := internal.DoubleNewLineCodec{}
			go jsonrpc2.NewConn(ctx, jsonrpc2.NewBufferedStream(conn, codec), &echoHandler{})
		}
	}()

	client, err := NewClient(ctx, socket)
	require.NoError(t, err)
	defer client.conn.Close()

	request := testParams{Foo: "data", Bar: 420}
	var response *testParams
	err = client.Call("mymethod", request, &response)
	require.NoError(t, err)
	assert.Equal(t, request.Foo, response.Foo)
	assert.Equal(t, request.Bar, response.Bar)
}

// TestClient_CallId checks that the Id is correctly increased on
// every call by the client.
func TestClient_CallId(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	socket := filepath.Join(dir, "test.socket")
	ctx := context.TODO()
	lis, err := net.Listen("unix", socket)
	require.NoError(t, err)
	defer lis.Close()

	handler := &echoHandler{}
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			codec := internal.DoubleNewLineCodec{}
			go jsonrpc2.NewConn(ctx, jsonrpc2.NewBufferedStream(conn, codec), handler)
		}
	}()

	client, err := NewClient(ctx, socket)
	require.NoError(t, err)
	defer client.conn.Close()

	nCalls := 100
	wg := sync.WaitGroup{}
	for i := 0; i < nCalls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request := testParams{Foo: "data", Bar: 420}
			var response *testParams
			err := client.Call("mymethod", request, &response)
			assert.NoError(t, err)
			assert.Equal(t, request.Foo, response.Foo)
			assert.Equal(t, request.Bar, response.Bar)
		}()

	}

	wg.Wait()
	handler.Lock()
	defer handler.Unlock()
	assert.Equal(t, nCalls, len(handler.ids))
	assert.EqualValues(t, nCalls, max(handler.ids))
}

func max(i []uint64) uint64 {
	var max uint64
	for _, v := range i {
		if v > max {
			max = v
		}
	}
	return max
}
