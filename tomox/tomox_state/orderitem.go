package tomox_state

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/log"
	"github.com/globalsign/mgo/bson"
	"math/big"
	"strconv"
	"time"
)

// OrderItem : info that will be store in database
type OrderItem struct {
	Quantity        *big.Int       `json:"quantity,omitempty"`
	Price           *big.Int       `json:"price,omitempty"`
	ExchangeAddress common.Address `json:"exchangeAddress,omitempty"`
	UserAddress     common.Address `json:"userAddress,omitempty"`
	BaseToken       common.Address `json:"baseToken,omitempty"`
	QuoteToken      common.Address `json:"quoteToken,omitempty"`
	Status          string         `json:"status,omitempty"`
	Side            string         `json:"side,omitempty"`
	Type            string         `json:"type,omitempty"`
	Hash            common.Hash    `json:"hash,omitempty"`
	Signature       *Signature     `json:"signature,omitempty"`
	FilledAmount    *big.Int       `json:"filledAmount,omitempty"`
	Nonce           *big.Int       `json:"nonce,omitempty"`
	PairName        string         `json:"pairName,omitempty"`
	CreatedAt       time.Time      `json:"createdAt,omitempty"`
	UpdatedAt       time.Time      `json:"updatedAt,omitempty"`
	OrderID         uint64         `json:"orderID,omitempty"`
	// *OrderMeta
	NextOrder []byte `json:"-"`
	PrevOrder []byte `json:"-"`
	OrderList []byte `json:"-"`
	Key       string `json:"key"`
}

// Signature struct
type Signature struct {
	V byte
	R common.Hash
	S common.Hash
}

type SignatureRecord struct {
	V byte   `json:"V" bson:"V"`
	R string `json:"R" bson:"R"`
	S string `json:"S" bson:"S"`
}

type OrderItemBSON struct {
	Quantity        string           `json:"quantity,omitempty" bson:"quantity"`
	Price           string           `json:"price,omitempty" bson:"price"`
	ExchangeAddress string           `json:"exchangeAddress,omitempty" bson:"exchangeAddress"`
	UserAddress     string           `json:"userAddress,omitempty" bson:"userAddress"`
	BaseToken       string           `json:"baseToken,omitempty" bson:"baseToken"`
	QuoteToken      string           `json:"quoteToken,omitempty" bson:"quoteToken"`
	Status          string           `json:"status,omitempty" bson:"status"`
	Side            string           `json:"side,omitempty" bson:"side"`
	Type            string           `json:"type,omitempty" bson:"type"`
	Hash            string           `json:"hash,omitempty" bson:"hash"`
	Signature       *SignatureRecord `json:"signature,omitempty" bson:"signature"`
	FilledAmount    string           `json:"filledAmount,omitempty" bson:"filledAmount"`
	Nonce           string           `json:"nonce,omitempty" bson:"nonce"`
	PairName        string           `json:"pairName,omitempty" bson:"pairName"`
	CreatedAt       time.Time        `json:"createdAt,omitempty" bson:"createdAt"`
	UpdatedAt       time.Time        `json:"updatedAt,omitempty" bson:"updatedAt"`
	OrderID         string           `json:"orderID,omitempty" bson:"orderID"`
	NextOrder       string           `json:"nextOrder,omitempty" bson:"nextOrder"`
	PrevOrder       string           `json:"prevOrder,omitempty" bson:"prevOrder"`
	OrderList       string           `json:"orderList,omitempty" bson:"orderList"`
	Key             string           `json:"key" bson:"key"`
}

func (o *OrderItem) GetBSON() (interface{}, error) {
	or := OrderItemBSON{
		PairName:        o.PairName,
		ExchangeAddress: o.ExchangeAddress.Hex(),
		UserAddress:     o.UserAddress.Hex(),
		BaseToken:       o.BaseToken.Hex(),
		QuoteToken:      o.QuoteToken.Hex(),
		Status:          o.Status,
		Side:            o.Side,
		Type:            o.Type,
		Hash:            o.Hash.Hex(),
		Quantity:        o.Quantity.String(),
		Price:           o.Price.String(),
		Nonce:           o.Nonce.String(),
		CreatedAt:       o.CreatedAt,
		UpdatedAt:       o.UpdatedAt,
		OrderID:         strconv.FormatUint(o.OrderID, 10),
		Key:             o.Key,
	}

	if o.FilledAmount != nil {
		or.FilledAmount = o.FilledAmount.String()
	}

	if o.Signature != nil {
		or.Signature = &SignatureRecord{
			V: o.Signature.V,
			R: o.Signature.R.Hex(),
			S: o.Signature.S.Hex(),
		}
	}

	return or, nil
}

func (o *OrderItem) SetBSON(raw bson.Raw) error {
	decoded := new(struct {
		ID              bson.ObjectId    `json:"id,omitempty" bson:"_id"`
		PairName        string           `json:"pairName" bson:"pairName"`
		ExchangeAddress string           `json:"exchangeAddress" bson:"exchangeAddress"`
		UserAddress     string           `json:"userAddress" bson:"userAddress"`
		BaseToken       string           `json:"baseToken" bson:"baseToken"`
		QuoteToken      string           `json:"quoteToken" bson:"quoteToken"`
		Status          string           `json:"status" bson:"status"`
		Side            string           `json:"side" bson:"side"`
		Type            string           `json:"type" bson:"type"`
		Hash            string           `json:"hash" bson:"hash"`
		Price           string           `json:"price" bson:"price"`
		Quantity        string           `json:"quantity" bson:"quantity"`
		FilledAmount    string           `json:"filledAmount" bson:"filledAmount"`
		Nonce           string           `json:"nonce" bson:"nonce"`
		MakeFee         string           `json:"makeFee" bson:"makeFee"`
		TakeFee         string           `json:"takeFee" bson:"takeFee"`
		Signature       *SignatureRecord `json:"signature" bson:"signature"`
		CreatedAt       time.Time        `json:"createdAt" bson:"createdAt"`
		UpdatedAt       time.Time        `json:"updatedAt" bson:"updatedAt"`
		OrderID         string           `json:"orderID" bson:"orderID"`
		Key             string           `json:"key" bson:"key"`
	})

	err := raw.Unmarshal(decoded)
	if err != nil {
		return err
	}

	o.PairName = decoded.PairName
	o.ExchangeAddress = common.HexToAddress(decoded.ExchangeAddress)
	o.UserAddress = common.HexToAddress(decoded.UserAddress)
	o.BaseToken = common.HexToAddress(decoded.BaseToken)
	o.QuoteToken = common.HexToAddress(decoded.QuoteToken)
	o.FilledAmount = ToBigInt(decoded.FilledAmount)
	o.Nonce = ToBigInt(decoded.Nonce)
	o.Status = decoded.Status
	o.Side = decoded.Side
	o.Type = decoded.Type
	o.Hash = common.HexToHash(decoded.Hash)

	if decoded.Quantity != "" {
		o.Quantity = ToBigInt(decoded.Quantity)
	}

	if decoded.FilledAmount != "" {
		o.FilledAmount = ToBigInt(decoded.FilledAmount)
	}

	if decoded.Price != "" {
		o.Price = ToBigInt(decoded.Price)
	}

	if decoded.Signature != nil {
		o.Signature = &Signature{
			V: byte(decoded.Signature.V),
			R: common.HexToHash(decoded.Signature.R),
			S: common.HexToHash(decoded.Signature.S),
		}
	}

	o.CreatedAt = decoded.CreatedAt
	o.UpdatedAt = decoded.UpdatedAt
	orderID, err := strconv.ParseInt(decoded.OrderID, 10, 64)
	if err == nil {
		fmt.Printf("%d of type %T", orderID, orderID)
	}
	o.OrderID = uint64(orderID)
	o.Key = decoded.Key

	return nil
}

func ToBigInt(s string) *big.Int {
	res := big.NewInt(0)
	res.SetString(s, 10)
	return res
}

// verify orderItem
func (o *OrderItem) VerifyOrder(state *state.StateDB) error {
	if err := o.VerifyBasicOrderInfo(); err != nil {
		return err
	}
	if err := o.verifyRelayer(state); err != nil {
		return err
	}
	return nil
}

func (o *OrderItem) VerifyBasicOrderInfo() error {
	if o.Type == Limit {
		if err := o.verifyPrice(); err != nil {
			return err
		}
	}
	if err := o.verifyQuantity(); err != nil {
		return err
	}
	if err := o.verifyOrderSide(); err != nil {
		return err
	}
	if err := o.verifyOrderType(); err != nil {
		return err
	}
	if err := o.verifySignature(); err != nil {
		return err
	}
	return nil
}

// verify whether the exchange applies to become relayer
func (o *OrderItem) verifyRelayer(state *state.StateDB) error {
	if !IsValidRelayer(state, o.ExchangeAddress) {
		return ErrInvalidRelayer
	}
	return nil
}

// following: https://github.com/tomochain/tomox-sdk/blob/master/types/order.go#L125
func (o *OrderItem) ComputeHash() common.Hash {
	sha := sha3.NewKeccak256()
	sha.Write(o.ExchangeAddress.Bytes())
	sha.Write(o.UserAddress.Bytes())
	sha.Write(o.BaseToken.Bytes())
	sha.Write(o.QuoteToken.Bytes())
	sha.Write(common.BigToHash(o.Quantity).Bytes())
	if o.Price != nil {
		sha.Write(common.BigToHash(o.Price).Bytes())
	}
	sha.Write(common.BigToHash(o.encodedSide()).Bytes())
	sha.Write(common.BigToHash(o.Nonce).Bytes())
	return common.BytesToHash(sha.Sum(nil))
}

//verify signatures
func (o *OrderItem) verifySignature() error {
	var (
		hash common.Hash
		err  error
	)
	hash = o.ComputeHash()
	if hash != o.Hash {
		log.Debug("Wrong orderhash", "expected", hex.EncodeToString(o.Hash.Bytes()), "actual", hex.EncodeToString(hash.Bytes()))
		return ErrWrongHash
	}
	message := crypto.Keccak256(
		[]byte("\x19Ethereum Signed Message:\n32"), // FIXME: Signature signed by EtherJS library, update this one if order is signed by other standards
		hash.Bytes(),
	)

	recoveredAddress, err := o.Signature.Verify(common.BytesToHash(message))
	if err != nil {
		log.Debug("failed to recover userAddress")
		return ErrInvalidSignature
	}
	if !bytes.Equal(recoveredAddress.Bytes(), o.UserAddress.Bytes()) {
		log.Debug("userAddress mismatch",
			"expected", hex.EncodeToString(o.UserAddress.Bytes()),
			"actual", hex.EncodeToString(recoveredAddress.Bytes()))
		return ErrInvalidSignature
	}
	return nil
}

// verify order type
func (o *OrderItem) verifyOrderType() error {
	if _, ok := MatchingOrderType[o.Type]; !ok {
		log.Debug("Invalid order type", "type", o.Type)
		return ErrInvalidOrderType
	}
	return nil
}

//verify order side
func (o *OrderItem) verifyOrderSide() error {

	if o.Side != Bid && o.Side != Ask {
		log.Debug("Invalid orderSide", "side", o.Side)
		return ErrInvalidOrderSide
	}
	return nil
}

func (o *OrderItem) encodedSide() *big.Int {
	if o.Side == Bid {
		return big.NewInt(0)
	}
	return big.NewInt(1)
}

// verifyPrice make sure price is a positive number
func (o *OrderItem) verifyPrice() error {
	if o.Price == nil || o.Price.Cmp(big.NewInt(0)) <= 0 {
		log.Debug("Invalid price", "price", o.Price.String())
		return ErrInvalidPrice
	}
	return nil
}

// verifyQuantity make sure quantity is a positive number
func (o *OrderItem) verifyQuantity() error {
	if o.Quantity == nil || o.Quantity.Cmp(big.NewInt(0)) <= 0 {
		log.Debug("Invalid quantity", "quantity", o.Quantity.String())
		return ErrInvalidQuantity
	}
	return nil
}

func IsValidRelayer(statedb *state.StateDB, address common.Address) bool {
	slot := RelayerMappingSlot["RELAYER_LIST"]
	locRelayerState := GetLocMappingAtKey(address.Hash(), slot)

	locBigDeposit := new(big.Int).SetUint64(uint64(0)).Add(locRelayerState, RelayerStructMappingSlot["_deposit"])
	locHashDeposit := common.BigToHash(locBigDeposit)
	balance := statedb.GetState(common.HexToAddress(common.RelayerRegistrationSMC), locHashDeposit).Big()
	if balance.Cmp(new(big.Int).SetUint64(uint64(0))) > 0 {
		return true
	}
	log.Debug("Balance of relayer is not enough", "relayer", address.String(), "balance", balance)
	return false
}

// MarshalSignature marshals the signature struct to []byte
func (s *Signature) MarshalSignature() ([]byte, error) {
	sigBytes1 := s.R.Bytes()
	sigBytes2 := s.S.Bytes()
	sigBytes3 := s.V - 27

	sigBytes := append([]byte{}, sigBytes1...)
	sigBytes = append(sigBytes, sigBytes2...)
	sigBytes = append(sigBytes, sigBytes3)

	return sigBytes, nil
}

// Verify returns the address that corresponds to the given signature and signed message
func (s *Signature) Verify(hash common.Hash) (common.Address, error) {

	hashBytes := hash.Bytes()
	sigBytes, err := s.MarshalSignature()
	if err != nil {
		return common.Address{}, err
	}

	pubKey, err := crypto.SigToPub(hashBytes, sigBytes)
	if err != nil {
		return common.Address{}, err
	}
	address := crypto.PubkeyToAddress(*pubKey)
	return address, nil
}
