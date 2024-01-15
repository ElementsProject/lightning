package rpc

import (
	"context"
	"net"
	"sync"
	"sync/atomic"

	"github.com/elementsproject/lightning/contrib/goln/internal"
	"github.com/sourcegraph/jsonrpc2"
)

type Client struct {
	mutex      sync.Mutex
	ctx        context.Context
	socketAddr string
	conn       *jsonrpc2.Conn
	unixConn   net.Conn

	lastId uint64
}

func NewClient(ctx context.Context, socketAddr string) (*Client, error) {
	client := &Client{ctx: ctx, socketAddr: socketAddr}
	if err := client.connect(); err != nil {
		return nil, err
	}
	return client, nil
}

func (client *Client) connect() error {
	client.mutex.Lock()
	defer client.mutex.Unlock()

	// We do not want to connect multiple times.
	if client.isConnected() {
		return nil
	}
	var err error
	client.unixConn, err = net.Dial("unix", client.socketAddr)
	if err != nil {
		return err
	}
	// client.conn.Close()
	client.conn, err = jsonrpc2.NewConn(client.ctx, jsonrpc2.NewBufferedStream(client.unixConn, internal.DoubleNewLineCodec{}), nil), nil
	return err
}

func (client *Client) isConnected() bool {
	if client.conn == nil {
		return false
	}
	buf := make([]byte, 1)
	_, err := client.unixConn.Read(buf)
	return err == nil
}

func (client *Client) nextId() uint64 {
	return atomic.AddUint64(&client.lastId, 1)
}

// Call allows for custom rpc calls, e.g. if one wants to call plugin rpc
// methods that do not have auto generated methods.
func (client *Client) Call(method string, params interface{}, result interface{}, opts ...jsonrpc2.CallOption) error {
	return client.conn.Call(client.ctx, method, params, result, jsonrpc2.PickID(jsonrpc2.ID{Num: client.nextId()}))
}

// Notify allows for custom rpc notifications.
func (client *Client) Notify(method string, params interface{}, opts ...jsonrpc2.CallOption) error {
	return client.conn.Notify(client.ctx, method, params, opts...)
}
