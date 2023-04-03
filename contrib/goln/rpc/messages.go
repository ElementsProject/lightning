package rpc

import "github.com/sourcegraph/jsonrpc2"

// Example model
type GetInfoRequest struct{}

// Example model
type GetInfoResponse struct {
	Id                  string        `json:"id"`
	Alias               string        `json:"alias"`
	Color               string        `json:"color"`
	NumPeers            int64         `json:"num_peers"`
	NumPendingChannels  int64         `json:"num_pending_channels"`
	NumActiveChannels   int64         `json:"num_active_channels"`
	NumInactiveChannels int64         `json:"num_inactive_channels"`
	Version             string        `json:"version"`
	Blockheight         int64         `json:"blockheight"`
	Network             string        `json:"network"`
	FeesCollectedMsat   string        `json:"fees_collected_msat"`
	LightningDir        string        `json:"lightning_dir"`
	Address             []interface{} `json:"address"`
}

func (client *Client) GetInfo(req GetInfoRequest, opts ...jsonrpc2.CallOption) (res *GetInfoResponse, err error) {
	err = client.Call("getinfo", req, &res, opts...)
	return
}
