package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOption(t *testing.T) {
	t.Parallel()

	t.Run("int64", func(t *testing.T) {
		t.Parallel()
		exp := int64(42)
		opt := IntOption("foo", exp, "bar")
		val, err := opt.GetIntValue()
		assert.NoError(t, err)
		assert.Equal(t, exp, val)

		_, err = opt.GetStringValue()
		assert.Error(t, err)

		_, err = opt.GetBoolValue()
		assert.Error(t, err)

		b, err := opt.MarshalJSON()
		assert.NoError(t, err)
		assert.Equal(t, `{"name":"foo","type":"int","default":42,"description":"bar"}`, string(b))
	})

	t.Run("string", func(t *testing.T) {
		t.Parallel()

		exp := "foobar"
		opt := StringOption("foo", exp, "bar")
		val, err := opt.GetStringValue()
		assert.NoError(t, err)
		assert.Equal(t, exp, val)

		_, err = opt.GetIntValue()
		assert.Error(t, err)

		_, err = opt.GetBoolValue()
		assert.Error(t, err)

		b, err := opt.MarshalJSON()
		assert.NoError(t, err)
		assert.Equal(t, `{"name":"foo","type":"string","default":"foobar","description":"bar"}`, string(b))
	})

	t.Run("bool", func(t *testing.T) {
		t.Parallel()

		exp := true
		opt := BoolOption("foo", exp, "bar")
		val, err := opt.GetBoolValue()
		assert.NoError(t, err)
		assert.Equal(t, exp, val)

		_, err = opt.GetIntValue()
		assert.Error(t, err)

		_, err = opt.GetStringValue()
		assert.Error(t, err)

		b, err := opt.MarshalJSON()
		assert.NoError(t, err)
		assert.Equal(t, `{"name":"foo","type":"bool","default":true,"description":"bar"}`, string(b))
	})

	t.Run("flag", func(t *testing.T) {
		t.Parallel()

		exp := true
		opt := BoolOption("foo", exp, "bar").Flag()
		val, err := opt.IsFlagged()
		assert.NoError(t, err)
		assert.Equal(t, exp, val)

		val, err = opt.GetBoolValue()
		assert.NoError(t, err)
		assert.Equal(t, exp, val)

		_, err = opt.GetIntValue()
		assert.Error(t, err)

		_, err = opt.GetStringValue()
		assert.Error(t, err)
	})
}
