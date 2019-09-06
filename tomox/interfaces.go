package tomox

import "github.com/ethereum/go-ethereum/common"

type OrderDao interface {
	IsEmptyKey(key []byte) bool
	Has(key []byte, dryrun uint64) (bool, error)
	Get(key []byte, val interface{}, dryrun uint64) (interface{}, error)
	Put(key []byte, val interface{}, dryrun uint64) error
	Delete(key []byte, dryrun uint64) error // won't return error if key not found
	InitDryRunVerifyMode()
	InitDryRunCommitNewWorkMode()
	SaveDryRunResult() error
	CancelOrder(hash common.Hash) error
}
