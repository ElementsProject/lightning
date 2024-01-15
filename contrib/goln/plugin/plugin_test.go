package plugin

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOption_Marshall checks marshalling of the command-line options that get
// passed to core-lightning.
func TestOption_Marshall(t *testing.T) {
	so := StringOption("so", "default", "description")
	b, err := json.Marshal(so)
	require.NoError(t, err)
	assert.Equal(t, `{"name":"so","type":"string","default":"default","description":"description"}`, string(b))

	io := IntOption("io", 123, "description").Deprecated()
	b, err = json.Marshal(io)
	require.NoError(t, err)
	assert.Equal(t, `{"name":"io","type":"int","default":123,"description":"description","deprecated":true}`, string(b))

	bo := BoolOption("bo", true, "description").Flag()
	b, err = json.Marshal(bo)
	require.NoError(t, err)
	assert.Equal(t, `{"name":"bo","type":"bool","default":true,"description":"description"}`, string(b))
}
