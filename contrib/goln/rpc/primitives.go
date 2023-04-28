package rpc

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type RoutehintList struct {
	Hints []RouteHint `json:"hints"`
}

type RouteHint struct {
	Hops []RouteHop `json:"hops"`
}

type RouteHop struct {
	// Required field.
	Id string `json:"id"`
	// Required field.
	Scid ShortChannelId `json:"scid"`
	// Required field.
	FeeBase Amount `json:"feebase"`
	// Required field.
	FeeProp uint32 `json:"feeprop"`
	// Required field.
	ExpiryDelta uint16 `json:"expirydelta"`
}

type TlvStream struct {
	Entries []TlvEntry
}

type TlvEntry struct {
	Typ   uint64
	Value []byte
}

func (t TlvStream) MarshalJSON() ([]byte, error) {
	es := make(map[uint64]string)
	for _, e := range t.Entries {
		es[e.Typ] = hex.EncodeToString(e.Value)
	}
	return json.Marshal(es)
}

func (t *TlvStream) UnmarshalJSON(b []byte) error {
	es := make(map[uint64]string)
	err := json.Unmarshal(b, &es)
	if err != nil {
		return err
	}

	var entries []TlvEntry
	for k, v := range es {
		hexB, err := hex.DecodeString(v)
		if err != nil {
			return err
		}
		entries = append(entries, TlvEntry{Typ: k, Value: hexB})
	}
	t.Entries = entries
	return nil
}

type ShortChannelId uint64

func (s ShortChannelId) Block() uint32 {
	return uint32(s>>40) & 0xFFFFFF
}

func (s ShortChannelId) TxIndex() uint32 {
	return uint32(s>>16) & 0xFFFFFF
}

func (s ShortChannelId) OutNum() uint16 {
	return uint16(s) & 0xFFFF
}

func (s ShortChannelId) String() string {
	return fmt.Sprintf("%dx%dx%d", s.Block(), s.TxIndex(), s.OutNum())
}

func (s *ShortChannelId) FromString(str string) error {
	parts := strings.Split(str, "x")
	if len(parts) != 3 {
		return fmt.Errorf("Malformed short_channel_id: %s", s)
	}
	var parsed []uint64
	for _, p := range parts {
		i, err := strconv.Atoi(p)
		if err != nil {
			return fmt.Errorf("Malformed short_channel_id: %s", s)
		}
		parsed = append(parsed, uint64(i))
	}
	*s = ShortChannelId((parsed[0] << 40) | (parsed[1] << 16) | (parsed[2] << 0))
	return nil
}

func (s ShortChannelId) MarshalJSON() ([]byte, error) {
	return []byte(s.String()), nil
}

func (s *ShortChannelId) UnmarshalJSON(b []byte) error {
	var j string
	err := json.Unmarshal(b, &j)
	if err != nil {
		return err
	}
	err = s.FromString(j)
	if err != nil {
		return err
	}
	return nil
}

// We internally always store an Amount as msat
type Amount uint64

func AmountFromMSat(msat uint64) Amount {
	return Amount(msat)
}

func AmountFromSat(sat uint64) Amount {
	return Amount(1_000 * sat)
}

func AmountFromBtc(btc uint64) Amount {
	return Amount(100_000_000_000 * btc)
}

// func (a Amount) IsAmountOrAll() {}
// func (a Amount) IsAmountOrAny() {}

// // AmountOrAll fields can be either of type `Amount` representing an msat value
// // or of type string with vale "all".
// type AmountOrAll interface {
// 	IsAmountOrAll()
// }

// type AmountAll struct{}

// func (a AmountAll) IsAmountOrAll() {}

// func (a AmountAll) MarshalJSON() ([]byte, error) {
// 	return json.Marshal("all")
// }

// // AmountOrAny fields can be either of type `Amount` representing an msat value
// // or of type string with vale "any".
// type AmountOrAny interface {
// 	IsAmountOrAny()
// }

// type AmountAny struct{}

// func (a AmountAny) IsAmountOrAny() {}

// func (a AmountAny) MarshalJSON() ([]byte, error) {
// 	return json.Marshal("any")
// }

type AmountOrAny struct {
	value interface{}
}

func AmountAny() AmountOrAny {
	return AmountOrAny{value: "any"}
}

func AmountOrAnyFromAmount(a Amount) AmountOrAny {
	return AmountOrAny{value: a}
}

func (a AmountOrAny) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.value)
}

func (a *AmountOrAny) UnmarshalJSON(b []byte) error {
	var i interface{}
	err := json.Unmarshal(b, &i)
	if err != nil {
		return err
	}
	switch t := i.(type) {
	case string:
		a.value = "any"
	case float64:
		a.value = Amount(uint64(t))
	case float32:
		a.value = Amount(uint64(t))
	case int:
		a.value = Amount(uint64(t))
	case int8:
		a.value = Amount(uint64(t))
	case int16:
		a.value = Amount(uint64(t))
	case int32:
		a.value = Amount(uint64(t))
	case int64:
		a.value = Amount(uint64(t))
	case uint:
		a.value = Amount(uint64(t))
	case uint8:
		a.value = Amount(uint64(t))
	case uint16:
		a.value = Amount(uint64(t))
	case uint32:
		a.value = Amount(uint64(t))
	case uint64:
		a.value = Amount(t)
	}
	return nil
}

type AmountOrAll struct {
	value interface{}
}

func AmountAll() AmountOrAll {
	return AmountOrAll{value: "all"}
}

func AmountOrAllFromAmount(a Amount) AmountOrAll {
	return AmountOrAll{value: a}
}

func (a AmountOrAll) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.value)
}

func (a *AmountOrAll) UnmarshalJSON(b []byte) error {
	var i interface{}
	err := json.Unmarshal(b, &i)
	if err != nil {
		return err
	}
	switch t := i.(type) {
	case string:
		a.value = "all"
	case float64:
		a.value = Amount(uint64(t))
	case float32:
		a.value = Amount(uint64(t))
	case int:
		a.value = Amount(uint64(t))
	case int8:
		a.value = Amount(uint64(t))
	case int16:
		a.value = Amount(uint64(t))
	case int32:
		a.value = Amount(uint64(t))
	case int64:
		a.value = Amount(uint64(t))
	case uint:
		a.value = Amount(uint64(t))
	case uint8:
		a.value = Amount(uint64(t))
	case uint16:
		a.value = Amount(uint64(t))
	case uint32:
		a.value = Amount(uint64(t))
	case uint64:
		a.value = Amount(t)
	}
	return nil
}

type FeeRateType string

const (
	FEERATE_NORMAL FeeRateType = "normal"
	FEERATE_SLOW   FeeRateType = "slow"
	FEERATE_URGENT FeeRateType = "urgent"
)

type FeeRate struct {
	value string
}

func FeeRatePerKw(n uint32) FeeRate {
	return FeeRate{value: fmt.Sprintf("%dperkw", n)}
}

func FeeRatePerKb(n uint32) FeeRate {
	return FeeRate{value: fmt.Sprintf("%dperkb", n)}
}

func FeeRateFromType(f FeeRateType) FeeRate {
	return FeeRate{value: string(f)}
}

func (f FeeRate) String() string {
	return f.value
}

func (f FeeRate) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.value)
}

func (f *FeeRate) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &f.value)
}
