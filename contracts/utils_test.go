// Copyright (c) 2018 Tomochain
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package contracts

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/contracts/blocksigner"
	"github.com/ethereum/go-ethereum/contracts/randomize"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"
	"math/rand"
	"testing"
	"time"
)

var (
	acc1Key, _ = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
	acc2Key, _ = crypto.HexToECDSA("49a7b37aa6f6645917e7b807e9d1c00d4fa71f18343b0d4122a4d2df64dd6fee")
	acc3Key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	acc4Key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee04aefe388d1e14474d32c45c72ce7b7a")
	acc1Addr   = crypto.PubkeyToAddress(acc1Key.PublicKey)
	acc2Addr   = crypto.PubkeyToAddress(acc2Key.PublicKey)
	acc3Addr   = crypto.PubkeyToAddress(acc3Key.PublicKey)
	acc4Addr   = crypto.PubkeyToAddress(acc4Key.PublicKey)
)

func getCommonBackend() *backends.SimulatedBackend {
	genesis := core.GenesisAlloc{acc1Addr: {Balance: big.NewInt(1000000000000)}}
	backend := backends.NewSimulatedBackend(genesis)
	backend.Commit()

	return backend
}

func TestSendTxSign(t *testing.T) {
	accounts := []common.Address{acc2Addr, acc3Addr, acc4Addr}
	keys := []*ecdsa.PrivateKey{acc2Key, acc3Key, acc4Key}
	backend := getCommonBackend()
	signer := types.HomesteadSigner{}
	ctx := context.Background()

	transactOpts := bind.NewKeyedTransactor(acc1Key)
	blockSignerAddr, blockSigner, err := blocksigner.DeployBlockSigner(transactOpts, backend, big.NewInt(99))
	if err != nil {
		t.Fatalf("Can't get block signer: %v", err)
	}
	backend.Commit()

	nonces := make(map[*ecdsa.PrivateKey]int)
	oldBlocks := make(map[common.Hash]common.Address)

	signTx := func(ctx context.Context, backend *backends.SimulatedBackend, signer types.HomesteadSigner, nonces map[*ecdsa.PrivateKey]int, accKey *ecdsa.PrivateKey, blockNumber *big.Int, blockHash common.Hash) *types.Transaction {
		tx, _ := types.SignTx(CreateTxSign(blockNumber, blockHash, uint64(nonces[accKey]), blockSignerAddr), signer, accKey)
		backend.SendTransaction(ctx, tx)
		backend.Commit()
		nonces[accKey]++

		return tx
	}

	// Tx sign for signer.
	signCount := int64(0)
	blockHashes := make([]common.Hash, 10)
	for i := int64(0); i < 10; i++ {
		blockHash := randomHash()
		blockHashes[i] = blockHash
		randIndex := rand.Intn(len(keys))
		accKey := keys[randIndex]
		signTx(ctx, backend, signer, nonces, accKey, new(big.Int).SetInt64(i), blockHash)
		oldBlocks[blockHash] = accounts[randIndex]
		signCount++

		// Tx sign for validators.
		for _, key := range keys {
			if key != accKey {
				signTx(ctx, backend, signer, nonces, key, new(big.Int).SetInt64(i), blockHash)
				signCount++
			}
		}
	}

	for _, blockHash := range blockHashes {
		signers, err := blockSigner.GetSigners(blockHash)
		if err != nil {
			t.Fatalf("Can't get signers: %v", err)
		}

		if signers[0].String() != oldBlocks[blockHash].String() {
			t.Errorf("Tx sign for block signer not match %v - %v", signers[0].String(), oldBlocks[blockHash].String())
		}

		if len(signers) != len(keys) {
			t.Error("Tx sign for block validators not match")
		}
	}
}

// Generate random string.
func randomHash() common.Hash {
	letterBytes := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"
	var b common.Hash
	for i := range b {
		rand.Seed(time.Now().UnixNano())
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return b
}

// Unit test for get random position of masternodes.
func TestRandomMasterNode(t *testing.T) {
	oldSlice := NewSlice(0, 10, 1)
	newSlice := Shuffle(oldSlice)
	for _, newNumber := range newSlice {
		for i, oldNumber := range oldSlice {
			if oldNumber == newNumber {
				// Delete find element.
				oldSlice = append(oldSlice[:i], oldSlice[i+1:]...)
			}
		}
	}
	if len(oldSlice) != 0 {
		t.Errorf("Test generate random masternode fail %v - %v", oldSlice, newSlice)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	//byteInteger := common.LeftPadBytes([]byte(new(big.Int).SetInt64(4).String()), 32)
	randomByte := RandStringByte(32)
	encrypt := Encrypt(randomByte, new(big.Int).SetInt64(4).String())
	decrypt := Decrypt(randomByte, encrypt)
	t.Log("Encrypt", encrypt, "Test", string(randomByte), "Decrypt", decrypt, "trim", string(bytes.TrimLeft([]byte(decrypt), "\x00")))
}

func TestSendTxRandomizeSecretAndOpening(t *testing.T) {
	backend := getCommonBackend()
	signer := types.HomesteadSigner{}
	ctx := context.Background()

	transactOpts := bind.NewKeyedTransactor(acc1Key)
	transactOpts.GasLimit = 4200000
	epocNumber := uint64(99)
	randomizeAddr, randomizeContract, err := randomize.DeployRandomize(transactOpts, backend, new(big.Int).SetInt64(99))
	if err != nil {
		t.Fatalf("Can't deploy randomize SC: %v", err)
	}
	backend.Commit()

	nonce := uint64(1)
	randomizeKeyValue := RandStringByte(32)
	tx, err := BuildTxSecretRandomize(nonce, randomizeAddr, epocNumber, randomizeKeyValue)
	if err != nil {
		t.Fatalf("Can't create tx randomize secret: %v", err)
	}
	tx, err = types.SignTx(tx, signer, acc1Key)
	if err != nil {
		t.Fatalf("Can't sign tx randomize secret: %v", err)
	}

	err = backend.SendTransaction(ctx, tx)
	if err != nil {
		t.Fatalf("Can't send tx for create randomize secret: %v", err)
	}
	backend.Commit()
	// Increment nonce.
	nonce++
	// Set opening.
	tx, err = BuildTxOpeningRandomize(nonce, randomizeAddr, randomizeKeyValue)
	if err != nil {
		t.Fatalf("Can't create tx randomize opening: %v", err)
	}
	tx, err = types.SignTx(tx, signer, acc1Key)
	if err != nil {
		t.Fatalf("Can't sign tx randomize opening: %v", err)
	}

	err = backend.SendTransaction(ctx, tx)
	if err != nil {
		t.Fatalf("Can't send tx for create randomize opening: %v", err)
	}
	backend.Commit()

	// Get randomize secret from SC.
	secretsArr, err := randomizeContract.GetSecret(acc1Addr)
	if err != nil {
		t.Fatalf("Can't get secret from SC: %v", err)
	}
	if len(secretsArr) <= 0 {
		t.Error("Empty get secrets from SC", err)
	}

	// Decrypt randomize from SC.
	secrets, err := randomizeContract.GetSecret(acc1Addr)
	if err != nil {
		t.Error("Fail get secrets from randomize", err)
	}
	opening, err := randomizeContract.GetOpening(acc1Addr)
	if err != nil {
		t.Fatalf("Can't get secret from SC: %v", err)
	}
	randomizes, err := decryptRandomizeFromSecretsAndOpening(secrets, opening)
	if err != nil {
		t.Error("Can't decrypt secret and opening", err)
	}
	if len(randomizes) != 991 {
		t.Error("Randomize length not match")
	}
}

func isArrayEqual(a [][]int64, b [][]int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i, vs := range a {
		for j, v := range vs {
			if v != b[i][j] {
				return false
			}
		}
	}
	return true
}

func TestTransposeMatrix(t *testing.T) {
	a := [][]int64{
		{0, 1, 2, 3, 4},
		{4, 5, 6, 7, 8},
	}
	b := [][]int64{
		{0, 4},
		{1, 5},
		{2, 6},
		{3, 7},
		{4, 8},
	}
	if !isArrayEqual(b, TransposeMatrix(a)) {
		t.Errorf("Fail to transpose matrix %v - %v", a, TransposeMatrix(a))
	}
}

func TestMultiMatrix(t *testing.T) {
	a := [][]int64{
		{1, -1, -1, 1, 1, -1},
	}
	b := make([][]int64, 6)
	for i := 0; i < len(a[0]); i++ {
		b[i] = Shuffle(NewSlice(0, 6, 1))
	}
	c, err := DotMatrix(a, b)
	if err != nil {
		t.Error("Fail to test dot matrix", err)
	}
	if len(a[0]) != len(c[0]) {
		t.Errorf("Fail to test dot matrix result %v - %v - %v", a, b, c)
	}
}

// Unit test for
func TestGenM2FromRandomize(t *testing.T) {
	a := [][]int64{
		{8, 4, 1, 5, 0, 3, 7, 6, 9, 2, 1},
		{4, 0, 8, 3, 1, 7, 9, 2, 5, 6, -1},
		{8, 1, 3, 2, 0, 9, 7, 4, 6, 5, -1},
		{2, 5, 4, 0, 6, 3, 1, 8, 7, 9, 1},
		{3, 7, 4, 1, 8, 2, 0, 9, 6, 5, 1},
		{1, 4, 8, 3, 7, 5, 2, 6, 0, 9, -1},
		{7, 4, 2, 0, 8, 1, 9, 6, 5, 3, 1},
		{4, 2, 5, 3, 1, 0, 7, 9, 6, 8, 1},
		{0, 2, 4, 7, 1, 8, 6, 3, 5, 9, -1},
		{7, 4, 3, 9, 1, 5, 0, 6, 8, 2, -1},
	}
	b, err := GenM2FromRandomize(a)
	if err != nil {
		t.Error("Fail to test gen m2 for randomize.", err)
	}
	c := []int64{6, 4, 0, 8, 5, 9, 1, 2, 0, 4}
	if !isArrayEqual([][]int64{b}, [][]int64{c}) {
		t.Errorf("Fail to get m2 result %v - %v", a, b)
	}
}
