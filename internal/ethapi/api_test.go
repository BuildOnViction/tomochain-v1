package ethapi

import (
	"context"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rpc"
	"math/big"
	"testing"
)

type MockBackend struct {
	chainConfig *params.ChainConfig
}

func (m MockBackend) Downloader() *downloader.Downloader {
	panic("implement me")
}

func (m MockBackend) ProtocolVersion() int {
	panic("implement me")
}

func (m MockBackend) SuggestPrice(ctx context.Context) (*big.Int, error) {
	panic("implement me")
}

func (m MockBackend) ChainDb() ethdb.Database {
	panic("implement me")
}

func (m MockBackend) EventMux() *event.TypeMux {
	panic("implement me")
}

func (m MockBackend) AccountManager() *accounts.Manager {
	panic("implement me")
}

func (m MockBackend) SetHead(number uint64) {
	panic("implement me")
}

func (m MockBackend) HeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Header, error) {
	panic("implement me")
}

func (m MockBackend) BlockByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*types.Block, error) {
	panic("implement me")
}

func (m MockBackend) StateAndHeaderByNumber(ctx context.Context, blockNr rpc.BlockNumber) (*state.StateDB, *types.Header, error) {
	panic("implement me")
}

func (m MockBackend) GetBlock(ctx context.Context, blockHash common.Hash) (*types.Block, error) {
	panic("implement me")
}

func (m MockBackend) GetReceipts(ctx context.Context, blockHash common.Hash) (types.Receipts, error) {
	panic("implement me")
}

func (m MockBackend) GetTd(blockHash common.Hash) *big.Int {
	panic("implement me")
}

func (m MockBackend) GetEVM(ctx context.Context, msg core.Message, state *state.StateDB, header *types.Header, vmCfg vm.Config) (*vm.EVM, func() error, error) {
	panic("implement me")
}

func (m MockBackend) SubscribeChainEvent(ch chan<- core.ChainEvent) event.Subscription {
	panic("implement me")
}

func (m MockBackend) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	panic("implement me")
}

func (m MockBackend) SubscribeChainSideEvent(ch chan<- core.ChainSideEvent) event.Subscription {
	panic("implement me")
}

func (m MockBackend) SendTx(ctx context.Context, signedTx *types.Transaction) error {
	panic("implement me")
}

func (m MockBackend) GetPoolTransactions() (types.Transactions, error) {
	panic("implement me")
}

func (m MockBackend) GetPoolTransaction(txHash common.Hash) *types.Transaction {
	panic("implement me")
}

func (m MockBackend) GetPoolNonce(ctx context.Context, addr common.Address) (uint64, error) {
	panic("implement me")
}

func (m MockBackend) Stats() (pending int, queued int) {
	panic("implement me")
}

func (m MockBackend) TxPoolContent() (map[common.Address]types.Transactions, map[common.Address]types.Transactions) {
	panic("implement me")
}

func (m MockBackend) SubscribeTxPreEvent(chan<- core.TxPreEvent) event.Subscription {
	panic("implement me")
}

func (m MockBackend) GetIPCClient() (*ethclient.Client, error) {
	panic("implement me")
}

func (m MockBackend) GetEngine() consensus.Engine {
	panic("implement me")
}

func (m MockBackend) GetRewardByHash(hash common.Hash) map[string]interface{} {
	panic("implement me")
}

func (m MockBackend) ChainConfig() *params.ChainConfig {
	return m.chainConfig
}

func (m MockBackend) CurrentBlock() *types.Block {
	header := &types.Header{
		Number: big.NewInt(3700),
	}
	return types.NewBlock(header, []*types.Transaction{}, []*types.Header{}, []*types.Receipt{})
}

func TestPublicBlockChainAPI_GetPreviousCheckpointFromEpoch(t *testing.T) {
	var ctx context.Context
	chainConfig := &params.ChainConfig{
		Posv: &params.PosvConfig{
			Epoch: uint64(900),
		},
	}
	var mockBackend Backend
	mockBackend = MockBackend{
		chainConfig,
	}
	s := &PublicBlockChainAPI{
		b: mockBackend,
	}

	if startEpoch1, _ := s.GetPreviousCheckpointFromEpoch(ctx, 1); startEpoch1 != 0 {
		t.Error("Epoch 1 should start at block 0", "result", startEpoch1)
	}

	if startEpoch2, _ := s.GetPreviousCheckpointFromEpoch(ctx, 2); startEpoch2 != 900 {
		t.Error("Epoch 2 should start at block 900", "result", startEpoch2)
	}

	if startEpoch5, _ := s.GetPreviousCheckpointFromEpoch(ctx, 5); startEpoch5 != 3600 {
		t.Error("Epoch 5 should start at block 3600", "result", startEpoch5)
	}
	if startCurrentEpoch, _ := s.GetPreviousCheckpointFromEpoch(ctx, rpc.LatestEpochNumber); startCurrentEpoch != 3600 {
		t.Error("CurrentBlockNumber: 3700. Current epoch should start at block 3600", "result", startCurrentEpoch)
	}
}
