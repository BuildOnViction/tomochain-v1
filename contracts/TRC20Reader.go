package contracts

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
)

var (
	slotTokenContractMapping = map[string]uint64{
		"balances":    0,
	}
)

func GetBalanceOf(statedb *state.StateDB, address common.Address, contractAddr common.Address) *big.Int {
	slot := slotTokenContractMapping["balance"]
	locBalance := getLocMappingAtKey(address.Hash(), slot)

	ret := statedb.GetState(contractAddr, common.BigToHash(locBalance))
	return ret.Big()
}
