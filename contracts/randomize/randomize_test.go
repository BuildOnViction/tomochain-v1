package randomize

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/contracts"
	"github.com/ethereum/go-ethereum/common"
)

var (
	epocNumber = int64(12)
	key, _     = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	addr       = crypto.PubkeyToAddress(key.PublicKey)
	byte0      = make([][32]byte, epocNumber)
)

func TestRandomize(t *testing.T) {
	contractBackend := backends.NewSimulatedBackend(core.GenesisAlloc{addr: {Balance: big.NewInt(100000000000000)}})
	transactOpts := bind.NewKeyedTransactor(key)
	transactOpts.GasLimit = 1000000

	_, randomize, err := DeployRandomize(transactOpts, contractBackend)
	if err != nil {
		t.Fatalf("can't deploy root registry: %v", err)
	}
	contractBackend.Commit()

	oldSlice := contracts.NewSlice(0, epocNumber-1, 1)
	newSlice := contracts.Shuffle(oldSlice)
	for i, v := range newSlice {
		bytes := common.LeftPadBytes(new(big.Int).SetInt64(v).Bytes(), 32)
		for j, b := range bytes {
			byte0[i][j] = b
		}
	}

	t.Log("byte0", byte0)
	s, err := randomize.SetSecret(byte0)
	if err != nil {
		t.Fatalf("can't set secret: %v", err)
	}
	t.Log("tx", s)
	contractBackend.Commit()
}
