package plugin

type GetManifestRequest struct {
	AllowDeprecatedApis bool `json:"allow-deprecated-apis"`
}

type GetManifestResponse struct {
	Options       []Option          `json:"options"`
	RpcMethods    []RpcMethod       `json:"rpcmethods"`
	Dynamic       bool              `json:"dynamic"`
	Subscriptions []string          `json:"subscriptions,omitempty"`
	Hooks         []Hook            `json:"hooks,omitempty"`
	FeatureBits   map[string]string `json:"featurebits,omitempty"`
}

type InitRequest struct {
	Options       map[string]interface{} `json:"options"`
	Configuration *Config                `json:"configuration"`
}

type InitResponse struct {
	Disable string `json:"disable,omitempty"`
}
