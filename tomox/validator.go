package tomox

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/log"
	"math/big"
)

var (
	// errors
	errWrongHash             = errors.New("verify order: wrong hash")
	errInvalidSignature      = errors.New("verify order: invalid signature")
	errInvalidPrice          = errors.New("verify order: invalid price")
	errInvalidQuantity       = errors.New("verify order: invalid quantity")
	errInvalidRelayer        = errors.New("verify order: invalid relayer")
	errInvalidOrderType      = errors.New("verify order: unsupported order type")
	errInvalidOrderSide      = errors.New("verify order: invalid order side")
	errOrderBookHashNotMatch = errors.New("verify order: orderbook hash not match")
	errOrderTreeHashNotMatch = errors.New("verify order: ordertree hash not match")

	// supported order types
	MatchingOrderType = map[string]bool{
		Market: true,
		Limit:  true,
	}
)

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
		return errInvalidRelayer
	}
	return nil
}

// following: https://github.com/tomochain/tomox-sdk/blob/master/types/order.go#L125
func (o *OrderItem) computeHash() common.Hash {
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
	sha.Write(common.StringToHash(o.Status).Bytes())
	sha.Write(common.StringToHash(o.Type).Bytes())
	return common.BytesToHash(sha.Sum(nil))
}

//verify signatures
func (o *OrderItem) verifySignature() error {
	var (
		hash common.Hash
		err  error
	)
	hash = o.computeHash()
	if hash != o.Hash {
		log.Debug("Wrong orderhash", "expected", hex.EncodeToString(o.Hash.Bytes()), "actual", hex.EncodeToString(hash.Bytes()))
		return errWrongHash
	}
	message := crypto.Keccak256(
		[]byte("\x19Ethereum Signed Message:\n32"), // FIXME: Signature signed by EtherJS library, update this one if order is signed by other standards
		hash.Bytes(),
	)

	recoveredAddress, err := o.Signature.Verify(common.BytesToHash(message))
	if err != nil {
		log.Debug("failed to recover userAddress")
		return errInvalidSignature
	}
	if !bytes.Equal(recoveredAddress.Bytes(), o.UserAddress.Bytes()) {
		log.Debug("userAddress mismatch",
			"expected", hex.EncodeToString(o.UserAddress.Bytes()),
			"actual", hex.EncodeToString(recoveredAddress.Bytes()))
		return errInvalidSignature
	}
	return nil
}

// verify order type
func (o *OrderItem) verifyOrderType() error {
	if _, ok := MatchingOrderType[o.Type]; !ok {
		log.Debug("Invalid order type", "type", o.Type)
		return errInvalidOrderType
	}
	return nil
}

//verify order side
func (o *OrderItem) verifyOrderSide() error {

	if o.Side != Bid && o.Side != Ask {
		log.Debug("Invalid orderSide", "side", o.Side)
		return errInvalidOrderSide
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
		return errInvalidPrice
	}
	return nil
}

// verifyQuantity make sure quantity is a positive number
func (o *OrderItem) verifyQuantity() error {
	if o.Quantity == nil || o.Quantity.Cmp(big.NewInt(0)) <= 0 {
		log.Debug("Invalid quantity", "quantity", o.Quantity.String())
		return errInvalidQuantity
	}
	return nil
}

func IsValidRelayer(statedb *state.StateDB, address common.Address) bool {
	slot := RelayerMappingSlot["RELAYER_LIST"]
	locRelayerState := getLocMappingAtKey(address.Hash(), slot)

	locBigDeposit := new(big.Int).SetUint64(uint64(0)).Add(locRelayerState, RelayerStructMappingSlot["_deposit"])
	locHashDeposit := common.BigToHash(locBigDeposit)
	balance := statedb.GetState(common.HexToAddress(common.RelayerRegistrationSMC), locHashDeposit).Big()
	if balance.Cmp(new(big.Int).SetUint64(uint64(0))) > 0 {
		return true
	}
	log.Debug("Balance of relayer is not enough", "relayer", address.String(), "balance", balance)
	return false
}

func GetTokenBalance(statedb *state.StateDB, address common.Address, contractAddr common.Address) *big.Int {
	slot := TokenMappingSlot["balances"]
	locBalance := getLocMappingAtKey(address.Hash(), slot)

	ret := statedb.GetState(contractAddr, common.BigToHash(locBalance))
	return ret.Big()
}

// verify orderbook, orderTrees before running matching engine
func (tx TxDataMatch) VerifyOldTomoXState(ob *OrderBook, dryrun bool, blockhash common.Hash) error {
	// verify orderbook
	if hash, err := ob.Hash(); err != nil || !bytes.Equal(hash.Bytes(), tx.ObOld.Bytes()) {
		log.Error("wrong old orderbook", "expected", hex.EncodeToString(tx.ObOld.Bytes()), "actual", hex.EncodeToString(hash.Bytes()), "err", err)
		return errOrderBookHashNotMatch
	}

	// verify order trees
	// bidTree tree
	bidTree := ob.Bids
	if hash, err := bidTree.Hash(dryrun, blockhash); err != nil || !bytes.Equal(hash.Bytes(), tx.BidOld.Bytes()) {
		log.Error("wrong old bid tree", "expected", hex.EncodeToString(tx.BidOld.Bytes()), "actual", hex.EncodeToString(hash.Bytes()), "err", err)
		return errOrderTreeHashNotMatch
	}
	// askTree tree
	askTree := ob.Asks
	if hash, err := askTree.Hash(dryrun, blockhash); err != nil || !bytes.Equal(hash.Bytes(), tx.AskOld.Bytes()) {
		log.Error("wrong old ask tree", "expected", hex.EncodeToString(tx.AskOld.Bytes()), "actual", hex.EncodeToString(hash.Bytes()), "err", err)
		return errOrderTreeHashNotMatch
	}
	return nil
}

// verify orderbook, orderTrees after running matching engine
func (tx TxDataMatch) VerifyNewTomoXState(ob *OrderBook, dryrun bool, blockhash common.Hash) error {
	// verify orderbook
	if hash, err := ob.Hash(); err != nil || !bytes.Equal(hash.Bytes(), tx.ObNew.Bytes()) {
		log.Error("wrong new orderbook", "expected", hex.EncodeToString(tx.ObNew.Bytes()), "actual", hex.EncodeToString(hash.Bytes()), "err", err)
		return errOrderBookHashNotMatch
	}

	// verify order trees
	// bidTree tree
	bidTree := ob.Bids
	if hash, err := bidTree.Hash(dryrun, blockhash); err != nil || !bytes.Equal(hash.Bytes(), tx.BidNew.Bytes()) {
		log.Error("wrong new bid tree", "expected", hex.EncodeToString(tx.BidNew.Bytes()), "actual", hex.EncodeToString(hash.Bytes()), "err", err)
		return errOrderTreeHashNotMatch
	}
	// askTree tree
	askTree := ob.Asks
	if hash, err := askTree.Hash(dryrun, blockhash); err != nil || !bytes.Equal(hash.Bytes(), tx.AskNew.Bytes()) {
		log.Error("wrong new ask tree", "expected", hex.EncodeToString(tx.AskNew.Bytes()), "actual", hex.EncodeToString(hash.Bytes()), "err", err)
		return errOrderTreeHashNotMatch
	}
	return nil
}

func (tx TxDataMatch) DecodeOrder() (*OrderItem, error) {
	order := &OrderItem{}
	if err := DecodeBytesItem(tx.Order, order); err != nil {
		return order, err
	}
	return order, nil
}

func (tx TxDataMatch) GetTrades() []map[string]string {
	return tx.Trades
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
