package rpc

import (
	"context"
	"log"
	"net"
	"sync"
	"sync/atomic"

	"github.com/elementsproject/lightning/contrib/goln/internal"
	"github.com/sourcegraph/jsonrpc2"
)

type Handler = func(context.Context, *jsonrpc2.Conn, *jsonrpc2.Request)

type Server struct {
	ctx     context.Context
	methods sync.Map
	run     int32
}

func NewServer(ctx context.Context) *Server {
	return &Server{ctx: ctx, methods: sync.Map{}, run: 1}
}

func (server *Server) Stop() {
	atomic.StoreInt32(&server.run, 0)
}

func (server *Server) isStopped() bool {
	return atomic.LoadInt32(&server.run) == 0
}

func (server *Server) Accept(lis net.Listener) {
	for {
		conn, err := lis.Accept()
		if err != nil {
			log.Print(err.Error())
			return
		}
		go jsonrpc2.NewConn(server.ctx, jsonrpc2.NewBufferedStream(conn, internal.DoubleNewLineCodec{}), server)
	}

}

func (server *Server) RegisterHandler(method string, handler Handler) {
	server.methods.Store(method, handler)
}

func (server *Server) UnregisterHandler(method string) {
	server.methods.Delete(method)
}

// Handle implements jsonrpc2.Handler
func (server *Server) Handle(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) {
	if server.isStopped() {
		_ = conn.ReplyWithError(ctx, req.ID, &jsonrpc2.Error{
			Code:    -32000,
			Message: "Server is stopped",
		})
		conn.Close()
		log.Print("Call of stopped server.")
		return
	}
	if method, ok := server.methods.Load(req.Method); ok {
		if handler, ok := method.(Handler); ok {
			handler(ctx, conn, req)
			return
		}
		log.Println("Associated handler is not of type Handler.")
	}
	_ = conn.ReplyWithError(ctx, req.ID, &jsonrpc2.Error{
		Code:    jsonrpc2.CodeMethodNotFound,
		Message: "Method not found",
	})
}
