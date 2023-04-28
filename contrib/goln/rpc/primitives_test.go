package rpc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

type AAA[T any] struct {
	AoA T `json:"amount_or"`
}

func amountOrXXXTestFunction[T any](a AAA[T]) string {
	b, _ := json.Marshal(a)
	return string(b)
}

func TestAmountOrAny(t *testing.T) {
	s := amountOrXXXTestFunction(AAA[AmountOrAny]{AoA: AmountOrAnyFromAmount(AmountFromSat(1))})
	assert.Equal(t, "{\"amount_or\":1000}", s)

	s = amountOrXXXTestFunction(AAA[AmountOrAny]{AoA: AmountAny()})
	assert.Equal(t, "{\"amount_or\":\"any\"}", s)
}

func TestAmountOrAll(t *testing.T) {
	s := amountOrXXXTestFunction(AAA[AmountOrAll]{AoA: AmountOrAllFromAmount(AmountFromBtc(1))})
	assert.Equal(t, "{\"amount_or\":100000000000}", s)

	s = amountOrXXXTestFunction(AAA[AmountOrAll]{AoA: AmountAll()})
	assert.Equal(t, "{\"amount_or\":\"all\"}", s)
}

func TestFeeRate(t *testing.T) {
	r := WithdrawRequest{
		Destination: "abc",
		Satoshi:     AmountOrAllFromAmount(AmountFromBtc(1)),
		Feerate:     FeeRateFromType(FEERATE_URGENT),
		Minconf:     12,
		Utxos:       []string{},
	}

	b, _ := json.Marshal(r)
	assert.Equal(t, "{\"destination\":\"abc\",\"satoshi\":100000000000,\"feerate\":\"urgent\",\"minconf\":12,\"utxos\":[]}", string(b))

	var w WithdrawRequest
	_ = json.Unmarshal(b, &w)
	assert.EqualValues(t, r, w)
}
