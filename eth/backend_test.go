package eth

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/tomox"
	"math/big"
	"testing"
)

func TestRewardInflation(t *testing.T) {
	for i := 0; i < 100; i++ {
		chainReward := new(big.Int).Mul(new(big.Int).SetUint64(250), new(big.Int).SetUint64(params.Ether))
		chainReward = rewardInflation(chainReward, uint64(i), 10)

		halfReward := new(big.Int).Mul(new(big.Int).SetUint64(125), new(big.Int).SetUint64(params.Ether))
		if 20 <= i && i < 60 && chainReward.Cmp(halfReward) != 0 {
			t.Error("Fail tor calculate reward inflation for 2 -> 5 years", "chainReward", chainReward)
		}

		quarterReward := new(big.Int).Mul(new(big.Int).SetUint64(62.5*1000), new(big.Int).SetUint64(params.Finney))
		if 60 <= i && chainReward.Cmp(quarterReward) != 0 {
			t.Error("Fail tor calculate reward inflation above 6 years", "chainReward", chainReward)
		}
	}
}


var db, _ = ethdb.NewMemDatabase()

func TestIsValidRelayer(t *testing.T) {
	order := &tomox.MatchingOrder{
		Buy: &tomox.OrderItem{
			ExchangeAddress: common.StringToAddress("relayer1"),
		},
	}
	var stateDb, _ = state.New(common.Hash{}, state.NewDatabase(db))
	// mockup an invalid relayer
	// has only 1 relayer in RelayerVotingSMC
	stateDb.SetState(common.StringToAddress(common.RelayerVotingSMC), common.BigToHash(big.NewInt(0)), common.BigToHash(big.NewInt(1)))
	slotKecBig := crypto.Keccak256Hash(common.BigToHash(big.NewInt(0)).Bytes()).Big()
	//arrBig = slotKecBig + index * elementSize
	arrBig := slotKecBig.Add(slotKecBig, new(big.Int).SetUint64(0))
	stateDb.SetState(common.StringToAddress(common.RelayerVotingSMC), common.BigToHash(arrBig), common.StringToHash("Invalid token address"))

	if err := isValidRelayer(order, stateDb); err != tomox.ErrInvalidRelayer {
		t.Error("TestIsValidRelayer FAILED. It should throw an error")
	}

	stateDb.SetState(common.StringToAddress(common.RelayerVotingSMC), common.BigToHash(arrBig), common.StringToHash("relayer1"))
	if err := isValidRelayer(order, stateDb); err != nil {
		t.Error("TestIsValidRelayer FAILED. Error should be nil")
	}
}

func TestValidateBalance(t *testing.T) {
	var stateDb, _ = state.New(common.Hash{}, state.NewDatabase(db))
	addr := common.StringToAddress("userAddress")
	tokenAdrr := common.StringToAddress("tokenAddr")
	// native tomo
	stateDb.SetBalance(addr, big.NewInt(99))

	if err := validateBalance(big.NewInt(100), addr, common.Address{}, stateDb); err != tomox.ErrNotEnoughBalance {
		t.Error("TestValidateBalance FAILED. Not enough TOMO. This order requires you have at least 100 TOMO")
	}
	if err := validateBalance(big.NewInt(95), addr, common.Address{}, stateDb); err != nil {
		t.Error("TestValidateBalance FAILED. This order just requires you have 95 TOMO")
	}

	// TRC20 tokens
	locBalance := new(big.Int)
	locBalance.SetBytes(crypto.Keccak256(addr.Hash().Bytes(), common.BigToHash(big.NewInt(0)).Bytes()))
	stateDb.SetState(tokenAdrr, common.BigToHash(locBalance), common.BigToHash(big.NewInt(98)))
	if err := validateBalance(big.NewInt(100), addr, tokenAdrr, stateDb); err != tomox.ErrNotEnoughBalance {
		t.Error("TestValidateBalance FAILED. Not enough TRC20 token. This order requires you have at least 100 tokens")
	}

	if err := validateBalance(big.NewInt(95), addr, tokenAdrr, stateDb); err != nil {
		t.Error("TestValidateBalance FAILED. This order just requires you have 95 tokens")
	}
}
