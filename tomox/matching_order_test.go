package tomox

import (
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"
	"testing"
	"time"
)

func TestMatchingOrder_ValidateSignature(t *testing.T) {
	// generate privateKey for buyer
	buyPrivateKey, _ := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
	buyPublicKey := buyPrivateKey.Public()
	buyPublicKeyECDSA, _ := buyPublicKey.(*ecdsa.PublicKey)
	buyPublicKeyBytes := crypto.FromECDSAPub(buyPublicKeyECDSA)

	// extract buyerAddress
	var buyAddress common.Address
	copy(buyAddress[:], crypto.Keccak256(buyPublicKeyBytes[1:])[12:])

	// generate privateKey for seller
	sellPrivateKey, _ := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a18")
	sellPublicKey := sellPrivateKey.Public()
	sellPublicKeyECDSA, _ := sellPublicKey.(*ecdsa.PublicKey)
	sellPublicKeyBytes := crypto.FromECDSAPub(sellPublicKeyECDSA)
	// extract sellerAddress
	var sellAddress common.Address
	copy(sellAddress[:], crypto.Keccak256(sellPublicKeyBytes[1:])[12:])

	order := &MatchingOrder{
		Buy: &Order{
			UserAddress: common.StringToAddress("aaa"), // assign arbitrary address
		},
		Sell: &Order{
			UserAddress: common.StringToAddress("aaa"), // assign arbitrary address
		},
	}
	// assign wrong hashes
	order.Buy.Hash, _ = order.HashBuyOrder()
	order.Sell.Hash, _ = order.HashSellOrder()

	var (
		buySignature, sellSignature Signature
		signatureBytes              []byte
	)
	signatureBytes, _ = crypto.Sign(order.Buy.Hash.Bytes(), buyPrivateKey)
	buySignature.R = common.BytesToHash(signatureBytes[0:32])
	buySignature.S = common.BytesToHash(signatureBytes[32:64])
	buySignature.V = signatureBytes[64] + 27
	order.Buy.Signature = &buySignature

	signatureBytes, _ = crypto.Sign(order.Sell.Hash.Bytes(), sellPrivateKey)
	sellSignature.R = common.BytesToHash(signatureBytes[0:32])
	sellSignature.S = common.BytesToHash(signatureBytes[32:64])
	sellSignature.V = signatureBytes[64] + 27
	order.Sell.Signature = &sellSignature

	// assign wrong hashes
	order.Buy.Hash = common.StringToHash("aaa")
	order.Sell.Hash = common.StringToHash("aaa")
	// wrong  both hashes of buyOrder
	if err := order.ValidateSignature(); err != ErrWrongHash {
		t.Error(err)
	}
	order.Buy.Hash, _ = order.HashBuyOrder()
	// update correct hash of buyOrder, now error is invalid signature of buyOrder
	if err := order.ValidateSignature(); err != ErrInvalidSignature {
		t.Error(err)
	}
	order.Buy.UserAddress = buyAddress
	// hash of sellOrder is still wrong
	if err := order.ValidateSignature(); err != ErrWrongHash {
		t.Error(err)
	}
	order.Sell.Hash, _ = order.HashSellOrder()
	// signature of sellOrder is still wrong
	if err := order.ValidateSignature(); err != ErrInvalidSignature {
		t.Error(err)
	}

	order.Sell.UserAddress = sellAddress
	// all are correct, should be Green
	if err := order.ValidateSignature(); err != nil {
		t.Error(err)
		t.Error("Wrong signature", err)
	}
	// assign wrong signature format to test recovery failed cases
	sellSignature.R = common.BytesToHash(signatureBytes[0:30])
	if err := order.ValidateSignature(); err != secp256k1.ErrRecoverFailed {
		t.Error(err)
	}
	buySignature.R = common.BytesToHash(signatureBytes[0:30])
	if err := order.ValidateSignature(); err != secp256k1.ErrRecoverFailed {
		t.Error(err)
	}
}

func TestMatchingOrder_ValidateOrderType(t *testing.T) {
	order := &MatchingOrder{
		Buy: &Order{
			Type: "XX",
		},
		Sell: &Order{
			Type: "XL",
		},
	}
	if err := order.ValidateOrderType(); err != ErrInvalidOrderType {
		t.Error("FAILED. XL is an invalid order type")
	}
	// update correct type to buyOrder
	// sellOrder is still invalid
	order.Buy.Type = Market
	if err := order.ValidateOrderType(); err != ErrInvalidOrderType {
		t.Error("FAILED.", err)
	}
	order.Sell.Type = Limit
	if err := order.ValidateOrderType(); err != nil {
		t.Error("FAILED.", err)
	}
}

func TestMatchingOrder_ValidateOrderSide(t *testing.T) {
	order := &MatchingOrder{
		Buy: &Order{
			Side: Ask,
		},
		Sell: &Order{
			Side: "aaa",
		},
	}
	if err := order.ValidateOrderSide(); err != ErrInvalidOrderSide {
		t.Error("FAILED. Order side should be BUY/SELL")
	}
	order.Buy.Side = Bid
	if err := order.ValidateOrderSide(); err != ErrInvalidOrderSide {
		t.Error("FAILED. Order side of sellOrder should be SELL")
	}
	order.Sell.Side = Ask
	if err := order.ValidateOrderSide(); err != nil {
		t.Error("FAILED.", err)
	}
}

func TestMatchingOrder_ValidateTimestamp(t *testing.T) {
	order := &MatchingOrder{
		Buy: &Order{
			CreatedAt: uint64(time.Now().Unix()) + 1000, // future time
			UpdatedAt: uint64(time.Now().Unix()) + 1000, // future time
		},
		Sell: &Order{
			CreatedAt: uint64(time.Now().Unix()) + 1000, // future time
			UpdatedAt: uint64(time.Now().Unix()) + 1000, // future time
		},
	}
	if err := order.ValidateTimestamp(); err != ErrFutureOrder {
		t.Error("FAILED. Receive a future order")
	}
	// update buyOrder
	order.Buy.CreatedAt = uint64(time.Now().Unix()) - 1000 // passed time
	order.Buy.UpdatedAt = uint64(time.Now().Unix()) - 1000 // passed time
	// still failed due to invalid timestamp of sellorder
	if err := order.ValidateTimestamp(); err != ErrFutureOrder {
		t.Error("FAILED. Receive a future order")
	}
	// update sellOrder
	order.Sell.CreatedAt = uint64(time.Now().Unix()) - 1000 // passed time
	order.Sell.UpdatedAt = uint64(time.Now().Unix()) - 1000 // passed time
	if err := order.ValidateTimestamp(); err != nil {
		t.Error("FAILED.", err)
	}
}

func TestMatchingOrder_ValidatePrice(t *testing.T) {
	order := &MatchingOrder{
		Buy: &Order{
			Price: big.NewInt(100),
		},
		Sell: &Order{
			Price: big.NewInt(105),
		},
		MatchedPrice: big.NewInt(90),
	}

	// buy: 100
	// sell: 105
	// matched: 90
	if err := order.ValidatePrice(); err != ErrInvalidPrice {
		t.Error("FAILED. BuyPrice should be greater than sellPrice")
	}

	// buy: 100
	// sell: 95
	// matched: 100
	// matchedPrice should be the better price
	order.MatchedPrice = big.NewInt(100)
	order.Sell.Price = big.NewInt(95)
	if err := order.ValidatePrice(); err != ErrInvalidPrice {
		t.Error("FAILED. MatchedPrice should be equal to buyPrice or sellPrice")
	}

	// buy: 100
	// sell: 95
	// matched: 95
	order.MatchedPrice = big.NewInt(95)
	if err := order.ValidatePrice(); err != nil {
		t.Error("FAILED.", err)
	}
}

func TestMatchingOrder_ValidateQuantity(t *testing.T) {
	order := &MatchingOrder{
		Buy: &Order{
			Quantity:     big.NewInt(100),
			FilledAmount: big.NewInt(90),
		},
		Sell: &Order{
			Quantity:     big.NewInt(105),
			FilledAmount: big.NewInt(80),
		},
		MatchedQuantity: big.NewInt(90),
	}
	if err := order.ValidateQuantity(); err != ErrFilledAmountNotMatch {
		t.Error("FAILED. Filled amount of buyOrder and sellOrder should be same")
	}

	// buy: 100
	// sell: 105
	// filled: 90
	order.Sell.FilledAmount = big.NewInt(90)
	if err := order.ValidateQuantity(); err != ErrInvalidFilledAmount {
		t.Error("FAILED. A successful order should clear quantity of smaller side")
	}

	// filledAmount = sellQuantity
	// buy: 100
	// sell: 90
	// filled: 90
	order.Sell.Quantity = big.NewInt(90)
	if err := order.ValidateQuantity(); err != nil {
		t.Error("FAILED.", err)
	}

	// filledAmount = buyAmount
	// buy: 100
	// sell: 110
	// filled: 100
	order.Buy.FilledAmount = big.NewInt(100)
	order.Sell.FilledAmount = big.NewInt(100)
	order.MatchedQuantity = big.NewInt(100)
	order.Sell.Quantity = big.NewInt(110)
	if err := order.ValidateQuantity(); err != nil {
		t.Error("FAILED.", err)
	}
}

func TestMatchingOrder_ValidatePairBySymbol(t *testing.T) {
	order := &MatchingOrder{
		Buy: &Order{
			PairName: "MAXBET/TOMO",
		},
		Sell: &Order{
			PairName: "ETH/TOMO",
		},
	}
	if err := order.ValidatePairBySymbol(); err != ErrWrongPair {
		t.Error("FAILED.", err)
	}
	order.Buy.PairName = "ETHTOMO"
	// wrong pairName format, should contain /
	if err := order.ValidatePairBySymbol(); err != ErrWrongPair {
		t.Error("FAILED.", err)
	}
	order.Buy.PairName = "ETH/TOMO"
	if err := order.ValidatePairBySymbol(); err != nil {
		t.Error("FAILED.", err)
	}
}

func TestMatchingOrder_ValidatePairByTokenAddress(t *testing.T) {
	order := &MatchingOrder{
		Buy: &Order{
			BaseToken:  common.StringToAddress("0x1111111111111111111111111"),
			QuoteToken: common.StringToAddress("0x2222222222222222222222222"),
		},
		Sell: &Order{
			BaseToken:  common.StringToAddress("0x1111111111111111111111111"),
			QuoteToken: common.StringToAddress("0x3333333333333333333333333"),
		},
	}
	if err := order.ValidatePairByTokenAddress(); err != ErrWrongPair {
		t.Error("FAILED. The error should be wrongPair")
	}
	order.Sell.QuoteToken = common.StringToAddress("0x2222222222222222222222222")
	if err := order.ValidatePairByTokenAddress(); err != nil {
		t.Error("FAILED.", err)
	}

	// validate with TOMO native
	order.Buy.BaseToken = common.Address{}
	if err := order.ValidatePairByTokenAddress(); err != ErrWrongPair {
		t.Error("FAILED. The error should be wrongPair")
	}
	order.Sell.BaseToken = common.Address{}
	if err := order.ValidatePairByTokenAddress(); err != nil {
		t.Error("FAILED.", err)
	}
}

func TestMatchingOrder_ValidateHash(t *testing.T) {
	order := &MatchingOrder{
		Buy: &Order{
			Price:     big.NewInt(100),
			CreatedAt: uint64(time.Now().Unix()) - 1000, // passed time
			UpdatedAt: uint64(time.Now().Unix()) - 1000, // passed time
		},
		Sell: &Order{
			Price:     big.NewInt(105),
			CreatedAt: uint64(time.Now().Unix()) - 1000, // passed time
			UpdatedAt: uint64(time.Now().Unix()) - 1000, // passed time
		},
		MatchedPrice: big.NewInt(90),
	}
	hash, _ := order.GetHash()
	order.Hash = hash
	// tamper a few information
	order.MatchedPrice = big.NewInt(110)

	if err := order.ValidateHash(); err != ErrWrongHash {
		t.Error("FAILED. Error should be wrong hash", err)
	}

	hash, _ = order.GetHash()
	order.Hash = hash
	if err := order.ValidateHash(); err != nil {
		t.Error("FAILED.", err)
	}
}
