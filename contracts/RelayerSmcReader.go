package contracts

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"math/big"
)


func IsValidRelayer(statedb *state.StateDB, coinbase common.Address) bool {
	//TODO: query smartcontract to check whether this is a valid relayer
	slot := uint64(0)
	slotHash := common.BigToHash(new(big.Int).SetUint64(slot))
	arrLength := statedb.GetState(common.StringToAddress(common.RelayerVotingSMC), slotHash)
	var keys []common.Hash
	for i := uint64(0); i < arrLength.Big().Uint64(); i++ {
		key := getLocDynamicArrAtElement(slotHash, i, 1)
		keys = append(keys, key)
	}
	for _, key := range keys {
		ret := statedb.GetState(common.StringToAddress(common.RelayerVotingSMC), key)
		if ret == coinbase.Hash() {
			return true
		}
	}

	return false
}
