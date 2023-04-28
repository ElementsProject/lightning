package plugin

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sourcegraph/jsonrpc2"
)

type OptionType string

const (
	OPTION_TYPE_STRING OptionType = "string"
	OPTION_TYPE_FLAG   OptionType = "flag"
	OPTION_TYPE_BOOL   OptionType = "bool"
	OPTION_TYPE_INT    OptionType = "int"
)

type allowedOptionTypes interface {
	~int64 | ~string | ~bool
}

type Option struct {
	name        string
	otype       OptionType
	value       interface{}
	vdefault    interface{}
	description string
	deprecated  bool
	isFlag      bool
}

func StringOption(name string, defaultValue string, description string) *Option {
	return &Option{
		name:        name,
		otype:       OPTION_TYPE_STRING,
		value:       defaultValue,
		vdefault:    defaultValue,
		description: description,
	}
}

func IntOption(name string, defaultValue int64, description string) *Option {
	return &Option{
		name:        name,
		otype:       OPTION_TYPE_INT,
		value:       defaultValue,
		vdefault:    defaultValue,
		description: description,
	}
}

func BoolOption(name string, defaultValue bool, description string) *Option {
	return &Option{
		name:        name,
		otype:       OPTION_TYPE_BOOL,
		value:       defaultValue,
		vdefault:    defaultValue,
		description: description,
	}
}

func (opt *Option) GetStringValue() (string, error) {
	return getOptionValue[string](opt)
}

func (opt *Option) GetIntValue() (int64, error) {
	return getOptionValue[int64](opt)
}

func (opt *Option) GetBoolValue() (bool, error) {
	return getOptionValue[bool](opt)
}

func (opt *Option) IsFlagged() (bool, error) {
	if opt.isFlag {
		return opt.GetBoolValue()
	}
	return false, fmt.Errorf("option is not a flag")
}

func getOptionValue[T allowedOptionTypes](opt *Option) (T, error) {
	val, ok := opt.value.(T)
	if !ok {
		return *new(T), fmt.Errorf("can not convert to to type %T", *new(T))
	}
	return val, nil
}

func (opt *Option) Deprecated() *Option {
	opt.deprecated = true
	return opt
}

func (opt *Option) Flag() *Option {
	opt.isFlag = true
	return opt
}

func (opt *Option) MarshalJSON() ([]byte, error) {
	switch opt.otype {
	case OPTION_TYPE_STRING:
		return marshalJSON[string](opt)
	case OPTION_TYPE_BOOL:
		return marshalJSON[bool](opt)
	case OPTION_TYPE_INT:
		return marshalJSON[int64](opt)
	default:
		return nil, fmt.Errorf("unknown option type")
	}
}

func marshalJSON[T allowedOptionTypes](opt *Option) ([]byte, error) {
	def, ok := opt.vdefault.(T)
	if !ok {
		return nil, fmt.Errorf("can not convert to to type %T", *new(T))
	}
	j := struct {
		Name        string     `json:"name"`
		Type        OptionType `json:"type"`
		Default     T          `json:"default"`
		Description string     `json:"description"`
		Deprecated  bool       `json:"deprecated,omitempty"`
		Categoty    string     `json:"category,omitempty"`
	}{
		Name:        opt.name,
		Type:        opt.otype,
		Default:     def,
		Description: opt.description,
		Deprecated:  opt.deprecated,
		Categoty:    "",
	}
	return json.Marshal(j)
}

type Callback = func(context.Context, *json.RawMessage) (interface{}, *jsonrpc2.Error)

type RpcMethod struct {
	name        string
	usage       string
	description string
	long        string
	deprecated  bool
	callback    Callback
}

func NewRpcMethod(name, usage, description, long string, callback Callback) *RpcMethod {
	return &RpcMethod{
		name:        name,
		usage:       usage,
		description: description,
		long:        long,
		deprecated:  false,
		callback:    callback,
	}
}

func (m *RpcMethod) Deprecated() *RpcMethod {
	m.deprecated = true
	return m
}

func (m *RpcMethod) MarshalJSON() ([]byte, error) {
	j := struct {
		Name            string `json:"name"`
		Usage           string `json:"usage"`
		Description     string `json:"description"`
		LongDescription string `json:"long_description"`
		Deprecated      bool   `json:"deprecated"`
	}{
		Name:            m.name,
		Usage:           m.usage,
		Description:     m.description,
		LongDescription: m.long,
		Deprecated:      m.deprecated,
	}
	return json.Marshal(j)
}

type Config struct {
	LightningDir string `json:"lightning-dir"`
	RpcFile      string `json:"rpc-file"`
	Startup      bool   `json:"startup"`
	Network      string `json:"network,omitempty"`
	FeatureSet   struct {
		Init    string `json:"init"`
		Node    string `json:"node"`
		Channel string `json:"channel"`
		Invoice string `json:"invoice"`
	} `json:"feature_set"`
	Proxy struct {
		Type string `json:"type,omitempty"`
		Addr string `json:"address,omitempty"`
		Port uint32 `json:"port,omitempty"`
	} `json:"proxy,omitempty"`
	TorV3Enabled   bool `json:"torv3-enabled,omitempty"`
	AlwaysUseProxy bool `json:"always_use_proxy,omitempty"`
}

type initData struct {
	conn    *jsonrpc2.Conn
	id      *jsonrpc2.ID
	request InitRequest
}

type HookType string

const (
	PEER_CONNECTED_HOOK        HookType = "peer_connected"
	COMMITMENT_REVOCATION_HOOK HookType = "commitment_revocation"
	DB_WRITE_HOOK              HookType = "db_write"
	INVOICE_PAYMENT_HOOK       HookType = "invoice_payment"
	OPEN_CHANNEL_HOOK          HookType = "openchannel"
	OPEN_CHANNEL_V2_HOOK       HookType = "openchannel2"
	OPEN_CHANNEL_V2_CHANGED    HookType = "openchannel2_changed"
	OPEN_CHANNEL_V2_SIGN       HookType = "openchannel2_sign"
	RBF_CHANNEL_HOOK           HookType = "rbf_channel"
	HTLC_ACCEPTED_HOOK         HookType = "htlc_accepted"
	RPC_COMMAND_HOOK           HookType = "rpc_command"
	CUSTOM_MSG_HOOK            HookType = "custommsg"
)

type Hook struct {
	typ      HookType
	callback Callback
	before   []string
}

func NewHook(typ HookType, callback Callback) *Hook {
	return &Hook{typ: typ, callback: callback, before: []string{}}
}

func (h *Hook) Before(plugin string) *Hook {
	h.before = append(h.before, plugin)
	return h
}

func (h *Hook) MarshalJSON() ([]byte, error) {
	j := struct {
		Name   string   `json:"name"`
		Before []string `json:"before,omitempty"`
	}{
		Name:   string(h.typ),
		Before: h.before,
	}
	return json.Marshal(j)
}
