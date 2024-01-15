package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/elementsproject/lightning/contrib/goln/rpc"

	"github.com/elementsproject/lightning/contrib/goln/internal"
	"github.com/sourcegraph/jsonrpc2"
)

type Builder struct {
	mu sync.Mutex

	in   io.ReadCloser
	out  io.WriteCloser
	stop chan struct{}

	server              *rpc.Server
	allowDeprecatedApis bool
	waitInit            chan initData

	options     map[string]*Option
	rpcMethods  map[string]*RpcMethod
	hooks       map[string]*Hook
	featureBits []*FeatureBits
	dynamic     bool
}

func NewBuilder(ctx context.Context, in io.ReadCloser, out io.WriteCloser) *Builder {
	builder := new(Builder)
	builder.in = in
	builder.out = out
	builder.stop = make(chan struct{}, 1)
	builder.server = rpc.NewServer(ctx)
	builder.waitInit = make(chan initData, 1)
	builder.options = make(map[string]*Option)
	builder.rpcMethods = make(map[string]*RpcMethod)
	builder.hooks = make(map[string]*Hook)
	builder.featureBits = []*FeatureBits{}

	// Register plugin startup rpc methods `getmanifest` and `init`.
	builder.server.RegisterHandler("getmanifest", builder.handleManifest)
	builder.server.RegisterHandler("init", builder.handleInit)

	return builder
}

func (builder *Builder) AddOption(o *Option) *Builder {
	builder.options[o.name] = o
	return builder
}

func (builder *Builder) AddRpcMethod(m *RpcMethod) *Builder {
	builder.rpcMethods[m.name] = m
	builder.server.RegisterHandler(m.name, func(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) {
		res, err := m.callback(ctx, req.Params)
		if err != nil {
			_ = conn.ReplyWithError(ctx, req.ID, err)
			return
		}
		_ = conn.Reply(ctx, req.ID, res)
	})
	return builder
}

func (builder *Builder) AddHook(h *Hook) *Builder {
	builder.hooks[string(h.typ)] = h
	builder.server.RegisterHandler(string(h.typ), func(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) {
		res, err := h.callback(ctx, req.Params)
		if err != nil {
			_ = conn.ReplyWithError(ctx, req.ID, err)
			return
		}
		_ = conn.Reply(ctx, req.ID, res)
	})
	return builder
}

func (builder *Builder) SetCustomFeatureBits(typ FeatureBitsType, bits string) *Builder {
	builder.featureBits = append(builder.featureBits, &FeatureBits{typ: typ, bits: bits})
	return builder
}

func (builder *Builder) Dynamic() *Builder {
	builder.dynamic = true
	return builder
}

func (builder *Builder) startServer() {
	lis := internal.NewReadWriteListener(builder.in, builder.out)
	builder.server.Accept(lis)
	// server.Accept is blocking. Once this returns we can send the
	// quit signal.
	builder.stop <- struct{}{}
}

func (builder *Builder) Configure() Plugin {
	// Start the server and wait for the `init` message.
	go builder.startServer()
	initData := <-builder.waitInit

	builder.mu.Lock()
	defer builder.mu.Unlock()

	// Unregister handler, we only needed them once.
	builder.server.UnregisterHandler("getmanifest")
	builder.server.UnregisterHandler("init")

	// Create new options map with returned values. Only append the returned
	// options, according to the deprecation settings.
	options := make(map[string]Option)
	for k, v := range initData.request.Options {
		if opt, ok := builder.options[k]; ok {
			options[k] = Option{
				name:        opt.name,
				otype:       opt.otype,
				value:       v,
				vdefault:    opt.vdefault,
				description: opt.description,
				deprecated:  opt.deprecated,
				isFlag:      opt.isFlag,
			}
		}
	}

	// Pass rpc-server, options and methods to the plugin.
	return Plugin{
		initConn:            initData.conn,
		initId:              initData.id,
		in:                  builder.in,
		out:                 builder.out,
		server:              builder.server,
		stop:                builder.stop,
		AllowDeprecatedApis: builder.allowDeprecatedApis,
		Config:              *initData.request.Configuration,
		Options:             options,
	}
}

func (builder *Builder) handleManifest(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) {
	var r GetManifestRequest
	err := json.Unmarshal(*req.Params, &r)
	if err != nil {
		_ = conn.ReplyWithError(ctx, req.ID, &jsonrpc2.Error{
			Code:    jsonrpc2.CodeInternalError,
			Message: fmt.Sprintf("could not unmarshal manifest: %s", err),
		})
		panic(fmt.Sprintf("could not unmarshal manifest: %s", err))
	}

	// Return GetManifestResponse to set the command-line options and the
	// custom rpc methods that get passed through.
	builder.mu.Lock()
	builder.allowDeprecatedApis = r.AllowDeprecatedApis

	// Create manifest response, set rpc methods. Options and rpc-methods only
	// are added to the manifest if they meet the deprecation settings.
	var result GetManifestResponse
	result.Dynamic = builder.dynamic
	for _, v := range builder.rpcMethods {
		if r.AllowDeprecatedApis || !v.deprecated {
			result.RpcMethods = append(result.RpcMethods, *v)
		}
	}
	for _, v := range builder.hooks {
		result.Hooks = append(result.Hooks, *v)
	}
	for _, v := range builder.options {
		if r.AllowDeprecatedApis || !v.deprecated {
			result.Options = append(result.Options, *v)
		}
	}
	result.FeatureBits = make(map[string]string)
	for _, v := range builder.featureBits {
		result.FeatureBits[string(v.typ)] = v.bits
	}

	builder.mu.Unlock()

	_ = conn.Reply(ctx, req.ID, result)
}

func (builder *Builder) handleInit(ctx context.Context, conn *jsonrpc2.Conn, req *jsonrpc2.Request) {
	var v InitRequest
	err := json.Unmarshal(*req.Params, &v)
	if err != nil {
		_ = conn.ReplyWithError(ctx, req.ID, &jsonrpc2.Error{
			Code:    jsonrpc2.CodeInternalError,
			Message: fmt.Sprintf("could not unmarshal init message: %s", err),
		})
		panic(fmt.Sprintf("could not unmarshal init message: %s", err))
	}
	builder.waitInit <- initData{
		conn:    conn,
		id:      &req.ID,
		request: v,
	}
}

type Plugin struct {
	mu sync.Mutex

	initConn *jsonrpc2.Conn
	initId   *jsonrpc2.ID

	in     io.ReadCloser
	out    io.WriteCloser
	server *rpc.Server
	stop   chan struct{}

	AllowDeprecatedApis bool
	Config              Config
	Options             map[string]Option
}

func (plugin *Plugin) Start() error {
	return plugin.answerInit("")
}

func (plugin *Plugin) Disable(msg string) error {
	return plugin.answerInit(msg)
}

func (plugin *Plugin) answerInit(disableMsg string) error {
	if plugin.initConn != nil && plugin.initId != nil {
		err := plugin.initConn.Reply(context.TODO(), *plugin.initId, InitResponse{Disable: disableMsg})
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("plugin has no init connection and/or init id")
	}
	plugin.initConn = nil
	plugin.initId = nil
	return nil
}

func (plugin *Plugin) Join() {
	<-plugin.stop
}
