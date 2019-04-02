package tomox

import (
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"math/big"
	"strings"
	"time"
)

type MatchingOrder struct {

	// buy order information
	Buy *OrderItem `json:"buy,omitempty"`

	// sell order information
	Sell *OrderItem `json:"sell,omitempty"`

	Hash common.Hash `json:"hash,omitempty"`

	// matching information
	MatchedPrice *big.Int `json:"matched_price,omitempty"`
	MatchedQuantity *big.Int `json:"matched_quantity,omitempty"`
}

var (
	// errors
	ErrUnsupportedEngine       = errors.New("only POSV supports matching orders")
	ErrFutureOrder             = errors.New("matching order: future order")
	ErrWrongHash               = errors.New("matching order: wrong hash")
	ErrDuplicatedMatchingOrder = errors.New("matching order: this order has been matched")
	ErrInvalidPrice            = errors.New("matching order: wrong price condition")
	ErrInvalidSignature        = errors.New("matching order: invalid signature")
	ErrInvalidFilledAmount     = errors.New("matching order: invalid filled amount")
	ErrFilledAmountNotMatch    = errors.New("matching order: filled amount of buyOrder and sellOrder are different")
	ErrNotEnoughBalance        = errors.New("matching order: not enough balance")
	ErrWrongPair               = errors.New("matching order: wrong pair")
	ErrInvalidRelayer          = errors.New("matching order: invalid relayer")
	ErrInvalidOrderType        = errors.New("matching order: unsupported order type: Limit/Market/Cancel")
	ErrInvalidOrderSide        = errors.New("matching order: invalid order side")

	// supported order types
	MatchingOrderType = map[string]bool{
		Market: true,
		Limit:  true,
	}
)

func (o MatchingOrder) HashBuyOrder() (common.Hash, error) {
	b, err := json.Marshal([]interface{}{
		o.Buy.OrderID,
		o.Buy.UserAddress,
		o.Buy.ExchangeAddress,
		o.Buy.BaseToken,
		o.Buy.QuoteToken,
		o.Buy.Status,
		o.Buy.Side,
		o.Buy.Type,
		o.Buy.Price,
		o.Buy.Quantity,
		o.Buy.FilledAmount,
		o.Buy.Nonce,
		o.Buy.MakeFee,
		o.Buy.TakeFee,
		o.Buy.PairName,
		o.Buy.CreatedAt,
		o.Buy.UpdatedAt,
	})
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(b), nil
}

func (o MatchingOrder) HashSellOrder() (common.Hash, error) {
	b, err := json.Marshal([]interface{}{
		o.Sell.OrderID,
		o.Sell.UserAddress,
		o.Sell.ExchangeAddress,
		o.Sell.BaseToken,
		o.Sell.QuoteToken,
		o.Sell.Status,
		o.Sell.Side,
		o.Sell.Type,
		o.Sell.Price,
		o.Sell.Quantity,
		o.Sell.FilledAmount,
		o.Sell.Nonce,
		o.Sell.MakeFee,
		o.Sell.TakeFee,
		o.Sell.PairName,
		o.Sell.CreatedAt,
		o.Sell.UpdatedAt,
	})
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(b), nil
}

func (o MatchingOrder) GetHash() (common.Hash, error) {
	b, err := json.Marshal([]interface{}{
		o.Buy,
		o.Sell,
		o.MatchedPrice,
		o.MatchedQuantity,
	})
	if err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(b), nil
}

/**********************
* validate signatures *
***********************/
func (o *MatchingOrder) ValidateSignature() error {
	// validate signature of buyOrder
	var (
		hash                                  common.Hash
		err                                   error
		buySignatureBytes, sellSignatureBytes []byte
	)
	hash, err = o.HashBuyOrder()
	if err != nil {
		return err
	}
	if hash != o.Buy.Hash {
		return ErrWrongHash
	}
	buySignatureBytes = append(buySignatureBytes, o.Buy.Signature.R.Bytes()...)
	buySignatureBytes = append(buySignatureBytes, o.Buy.Signature.S.Bytes()...)
	buySignatureBytes = append(buySignatureBytes, o.Buy.Signature.V-27)
	buyPubkey, err := crypto.Ecrecover(hash.Bytes(), buySignatureBytes)
	if err != nil {
		return err
	}
	var buyAddress common.Address
	copy(buyAddress[:], crypto.Keccak256(buyPubkey[1:])[12:])
	if buyAddress != o.Buy.UserAddress {
		return ErrInvalidSignature
	}

	// validate signature of sellOrder
	hash, err = o.HashSellOrder()
	if err != nil {
		return err
	}
	if hash != o.Sell.Hash {
		return ErrWrongHash
	}

	sellSignatureBytes = append(sellSignatureBytes, o.Sell.Signature.R.Bytes()...)
	sellSignatureBytes = append(sellSignatureBytes, o.Sell.Signature.S.Bytes()...)
	sellSignatureBytes = append(sellSignatureBytes, o.Sell.Signature.V-27)
	sellPubkey, err := crypto.Ecrecover(hash.Bytes(), sellSignatureBytes)
	if err != nil {
		return err
	}
	var sellAddress common.Address
	copy(sellAddress[:], crypto.Keccak256(sellPubkey[1:])[12:])
	if sellAddress != o.Sell.UserAddress {
		return ErrInvalidSignature
	}
	return nil
}

/**********************
* validate order type *
***********************/
func (o *MatchingOrder) ValidateOrderType() error {

	if _, ok := MatchingOrderType[o.Buy.Type]; !ok {
		return ErrInvalidOrderType
	}
	if _, ok := MatchingOrderType[o.Sell.Type]; !ok {
		return ErrInvalidOrderType
	}
	return nil
}

/**********************
* validate order side *
***********************/
func (o *MatchingOrder) ValidateOrderSide() error {

	if o.Buy.Side != Bid {
		return ErrInvalidOrderSide
	}
	if o.Sell.Side != Ask {
		return ErrInvalidOrderSide
	}
	return nil
}

/********************
* validate hash		*
*********************/
func (o *MatchingOrder) ValidateHash() error {
	h, err := o.GetHash()
	if err != nil {
		return err
	}
	if h != o.Hash {
		return ErrWrongHash
	}
	return nil
}

/*********************
* validate timestamp *
**********************/
func (o *MatchingOrder) ValidateTimestamp() error {
	// check timestamp of buyOrder
	if o.Buy.CreatedAt == 0 || o.Buy.CreatedAt > uint64(time.Now().Unix()) || o.Buy.UpdatedAt == 0 || o.Buy.UpdatedAt > uint64(time.Now().Unix()) {
		return ErrFutureOrder
	}
	// check timestamp of sellOrder
	if o.Sell.CreatedAt == 0 || o.Sell.CreatedAt > uint64(time.Now().Unix()) || o.Sell.UpdatedAt == 0 || o.Sell.UpdatedAt > uint64(time.Now().Unix()) {
		return ErrFutureOrder
	}
	return nil
}

/****************************************************************
*	validate price												*
*	a valid order should match both 2 following conditions     	*
* 		buyPrice >= matchedPrice >= sellPrice                 	*
*		matchedPrice is exactly equal buyPrice or sellPrice   	*
*****************************************************************/

func (o *MatchingOrder) ValidatePrice() error {
	if o.Buy.Price.Cmp(o.Sell.Price) < 0 {
		return ErrInvalidPrice
	}
	betterPrice := o.Buy.Price
	if o.Sell.Price.Cmp(betterPrice) < 0 {
		betterPrice = o.Sell.Price
	}
	if o.MatchedPrice.Cmp(betterPrice) != 0 {
		return ErrInvalidPrice
	}
	return nil
}

/****************************************************************
*  validate Quantity											*
* 		Quantity of at least one side must be cleared		  	*
*****************************************************************/
func (o *MatchingOrder) ValidateQuantity() error {
	if o.Buy.FilledAmount.Cmp(o.Sell.FilledAmount) != 0 {
		return ErrFilledAmountNotMatch
	}
	smaller := o.Buy.Quantity
	if o.Sell.Quantity.Cmp(smaller) < 0 {
		smaller = o.Sell.Quantity
	}
	if smaller.Cmp(o.Buy.FilledAmount) != 0 || smaller.Cmp(o.MatchedQuantity) != 0 {
		return ErrInvalidFilledAmount
	}
	return nil
}

/****************************************
*	validate pair by token address		*
*****************************************/
func (o *MatchingOrder) ValidatePairByTokenAddress() error {
	// valid pair by smc address
	if o.Buy.QuoteToken != o.Sell.QuoteToken || o.Buy.BaseToken != o.Sell.BaseToken {
		log.Error("Matching order: Failed to validate pair by smartcontract address", "BuyQuoteContract", o.Buy.QuoteToken, "SellQuoteContract", o.Sell.QuoteToken, "SellBaseContract", o.Sell.BaseToken)
		return ErrWrongPair
	}
	return nil
}

/****************************************
*	validate pair by symbol		*
*****************************************/
func (o *MatchingOrder) ValidatePairBySymbol() error {
	// validate pair by symbol
	if !strings.Contains(o.Buy.PairName, "/") || !strings.Contains(o.Sell.PairName, "/") {
		log.Error("Matching order: Invalid pairName syntax", "buy", o.Buy.PairName, "sell", o.Sell.PairName)
		return ErrWrongPair
	}
	buySymbols := strings.Split(o.Buy.PairName, "/")
	buyBaseSymbol, buyQuoteSymbol := buySymbols[0], buySymbols[1]
	sellSymbols := strings.Split(o.Sell.PairName, "/")
	sellBaseSymbol, sellQuoteSymbol := sellSymbols[0], sellSymbols[1]

	if buyBaseSymbol != sellBaseSymbol || buyQuoteSymbol != sellQuoteSymbol {
		log.Error("Matching order: Failed to validate pair by symbol", "buyBaseSymbol", buyBaseSymbol, "buyQuoteSymbol", buyQuoteSymbol, "sellBaseSymbol", sellBaseSymbol, "sellQuoteSymbol", sellQuoteSymbol)
		return ErrWrongPair
	}
	return nil
}

/**********************
* validate relayer    *
***********************/
//func (o *MatchingOrder) IsSameRelayer() error {
//	// same coinbase address of relayer
//	if o.Buy.ExchangeAddress != o.Sell.ExchangeAddress {
//		return ErrRelayerNotMatch
//	}
//	return nil
//}
