package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/elementsproject/lightning/contrib/goln/internal"
	"github.com/elementsproject/lightning/contrib/goln/plugin"
	"github.com/sourcegraph/jsonrpc2"
)

func init() {
	c := jsonrpc2.NewConn(
		context.Background(),
		jsonrpc2.NewBufferedStream(
			internal.NewReadWriterConn(internal.EOFReader{}, os.Stdout),
			internal.DoubleNewLineCodec{},
		),
		nil,
	)
	plugin.InitDefaultLogger(c, plugin.LEVEL_DEBUG)
	log.Printf("Init logging.")
}

func main() {
	quit := make(chan struct{})
	log.Println("Starting plugin.")
	builder := plugin.NewBuilder(context.Background(), os.Stdin, os.Stdout).
		AddOption(plugin.IntOption("my-option", 42, "This is an option (default: 42).")).
		AddOption(plugin.StringOption("my-deprecated-option", "default-value", "This option is deprecated.").Deprecated()).
		AddRpcMethod(plugin.NewRpcMethod("test-rpc-method", "amt scid", "description", "long description", myCallback))
	plugin := builder.Configure()
	err := plugin.Start()
	if err != nil {
		panic(fmt.Sprintf("Got error: %s", err))
	}
	log.Println("Plugin initialized.")
	<-quit
}

func myCallback(ctx context.Context, req *json.RawMessage) (interface{}, *jsonrpc2.Error) {
	return CallbackResponse{
		Got:      string(*req),
		Number:   100,
		AndABool: false,
	}, nil
}

type CallbackResponse struct {
	Got      string `json:"request"`
	Number   int32  `json:"number"`
	AndABool bool   `json:"boolean"`
}
