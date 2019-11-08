package tomox

import (
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/tomox/tomox_state"
	"math/big"
	"strconv"
)

type Comparator func(a, b []byte) int
type EncodeToBytes func(interface{}) ([]byte, error)
type DecodeBytes func([]byte, interface{}) error
type FormatBytes func([]byte) string

const (
	TrueByte  = byte(1)
	FalseByte = byte(0)
	decimals  = 18
	Ask       = "SELL"
	Bid       = "BUY"
	Market    = "MO"
	Limit     = "LO"
	Cancel    = "CANCELLED"
)

var (
	TokenMappingSlot = map[string]uint64{
		"balances": 0,
	}
	RelayerMappingSlot = map[string]uint64{
		"CONTRACT_OWNER":       0,
		"MaximumRelayers":      1,
		"MaximumTokenList":     2,
		"RELAYER_LIST":         3,
		"RELAYER_COINBASES":    4,
		"RESIGN_REQUESTS":      5,
		"RELAYER_ON_SALE_LIST": 6,
		"RelayerCount":         7,
		"MinimumDeposit":       8,
	}
	RelayerStructMappingSlot = map[string]*big.Int{
		"_deposit":    big.NewInt(0),
		"_fee":        big.NewInt(1),
		"_fromTokens": big.NewInt(2),
		"_toTokens":   big.NewInt(3),
		"_index":      big.NewInt(4),
		"_owner":      big.NewInt(5),
	}
)

var (
	// errors
	ErrUnsupportedEngine    = errors.New("only POSV supports matching orders")
	ErrTomoXServiceNotFound = errors.New("can't attach tomoX service")
	ErrInvalidDryRunResult  = errors.New("failed to apply txMatches, invalid dryRun result")
)

type OrderHistoryItem struct {
	TxHash       common.Hash
	FilledAmount *big.Int
	Status       string
}

// use alloc to prevent reference manipulation
func EmptyKey() []byte {
	key := make([]byte, common.HashLength)
	return key
}

func GetSegmentHash(key []byte, segment, index uint8) []byte {
	keyLength := len(key)
	segmentKey := make([]byte, keyLength)
	copy(segmentKey, key)
	segmentKey[index] = byte(uint8(segmentKey[index]) + segment)

	return segmentKey
}

func Bool2byte(bln bool) byte {
	if bln == true {
		return TrueByte
	}

	return FalseByte
}

func Byte2bool(b byte) bool {
	if b == TrueByte {
		return true
	}
	return false
}

// ToJSON : log json string
func ToJSON(object interface{}, args ...string) string {
	var str []byte
	if len(args) == 2 {
		str, _ = json.MarshalIndent(object, args[0], args[1])
	} else {
		str, _ = json.Marshal(object)
	}
	return string(str)
}

func GetKeyFromUint64(key uint64) []byte {
	return GetKeyFromBig(big.NewInt(int64(key)))
}

func GetKeyFromString(key string) []byte {
	var bigInt *big.Int
	// this is too big, maybe hash string
	if len(key) >= 2*common.AddressLength {
		// if common.IsHexAddress(key) {
		// 	return common.HexToHash().Bytes()
		// }
		bigInt = new(big.Int).SetBytes([]byte(key))
	} else {
		bigInt, _ = new(big.Int).SetString(key, 10)
	}
	return GetKeyFromBig(bigInt)
}

func GetKeyFromBig(key *big.Int) []byte {
	return common.BigToHash(key).Bytes()
}

func Mul(x, y *big.Int) *big.Int {
	return big.NewInt(0).Mul(x, y)
}

func Div(x, y *big.Int) *big.Int {
	return big.NewInt(0).Div(x, y)
}

func Add(x, y *big.Int) *big.Int {
	return big.NewInt(0).Add(x, y)
}

func Sub(x, y *big.Int) *big.Int {
	return big.NewInt(0).Sub(x, y)
}

func Neg(x *big.Int) *big.Int {
	return big.NewInt(0).Neg(x)
}

func ToBigInt(s string) *big.Int {
	res := big.NewInt(0)
	res.SetString(s, 10)
	return res
}

func CloneBigInt(bigInt *big.Int) *big.Int {
	res := new(big.Int).SetBytes(bigInt.Bytes())
	return res
}

func Exp(x, y *big.Int) *big.Int {
	return big.NewInt(0).Exp(x, y, nil)
}

func BigIntToBigFloat(a *big.Int) *big.Float {
	b := new(big.Float).SetInt(a)
	return b
}

func ToDecimal(value *big.Int) float64 {
	bigFloatValue := BigIntToBigFloat(value)
	result := DivFloat(bigFloatValue, big.NewFloat(1e18))

	floatValue, _ := result.Float64()
	return floatValue
}

func DivFloat(x, y *big.Float) *big.Float {
	return big.NewFloat(0).Quo(x, y)
}

func Max(a, b *big.Int) *big.Int {
	if a.Cmp(b) == 1 {
		return a
	} else {
		return b
	}
}

func Zero() *big.Int {
	return big.NewInt(0)
}

func IsZero(x *big.Int) bool {
	if x.Cmp(big.NewInt(0)) == 0 {
		return true
	} else {
		return false
	}
}

func IsEqual(x, y *big.Int) bool {
	if x.Cmp(y) == 0 {
		return true
	} else {
		return false
	}
}

func CmpBigInt(a []byte, b []byte) int {
	x := new(big.Int).SetBytes(a)
	y := new(big.Int).SetBytes(b)
	return x.Cmp(y)
}

func IsGreaterThan(x, y *big.Int) bool {
	if x.Cmp(y) == 1 || x.Cmp(y) == 0 {
		return true
	} else {
		return false
	}
}

func IsStrictlyGreaterThan(x, y *big.Int) bool {
	if x.Cmp(y) == 1 {
		return true
	} else {
		return false
	}
}

func IsSmallerThan(x, y *big.Int) bool {
	if x.Cmp(y) == -1 || x.Cmp(y) == 0 {
		return true
	} else {
		return false
	}
}

func IsStrictlySmallerThan(x, y *big.Int) bool {
	if x.Cmp(y) == -1 {
		return true
	} else {
		return false
	}
}

func IsEqualOrGreaterThan(x, y *big.Int) bool {
	return (IsEqual(x, y) || IsGreaterThan(x, y))
}

func IsEqualOrSmallerThan(x, y *big.Int) bool {
	return (IsEqual(x, y) || IsSmallerThan(x, y))
}

func EncodeTxMatchesBatch(txMatchBatch TxMatchBatch) ([]byte, error) {
	data, err := json.Marshal(txMatchBatch)
	if err != nil || data == nil {
		return []byte{}, err
	}
	return data, nil
}

func DecodeTxMatchesBatch(data []byte) (TxMatchBatch, error) {
	txMatchResult := TxMatchBatch{}
	if err := json.Unmarshal(data, &txMatchResult); err != nil {
		return TxMatchBatch{}, err
	}
	return txMatchResult, nil
}

func GetOrderHistoryKey(baseToken, quoteToken common.Address, orderId uint64) common.Hash {
	return crypto.Keccak256Hash(baseToken.Bytes(), quoteToken.Bytes(), []byte(strconv.FormatUint(orderId, 10)))
}
func (tx TxDataMatch) DecodeOrder() (*tomox_state.OrderItem, error) {
	order := &tomox_state.OrderItem{}
	if err := DecodeBytesItem(tx.Order, order); err != nil {
		return order, err
	}
	return order, nil
}

func (tx TxDataMatch) GetTrades() []map[string]string {
	return tx.Trades
}

func (tx TxDataMatch) GetRejectedOrders() []*tomox_state.OrderItem {
	return tx.RejectedOders
}

func GetOrderBookHash(baseToken common.Address, quoteToken common.Address) common.Hash {
	return common.BytesToHash(append(baseToken[:16], quoteToken[4:]...))
}
