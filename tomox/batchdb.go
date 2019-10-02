package tomox

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	lru "github.com/hashicorp/golang-lru"
	"github.com/pkg/errors"
)

const (
	defaultCacheLimit = 1024000
)

type BatchItem struct {
	Value interface{}
}

type BatchDatabase struct {
	db           *ethdb.LDBDatabase
	emptyKey     []byte
	cacheItems   *lru.Cache // Cache for reading
	dryRunCaches map[common.Hash]*lru.Cache
	lock         sync.RWMutex
	cacheLimit   int
	Debug        bool
}

// NewBatchDatabase use rlp as encoding
func NewBatchDatabase(datadir string, cacheLimit int) *BatchDatabase {
	return NewBatchDatabaseWithEncode(datadir, cacheLimit)
}

// batchdatabase is a fast cache db to retrieve in-mem object
func NewBatchDatabaseWithEncode(datadir string, cacheLimit int) *BatchDatabase {
	db, err := ethdb.NewLDBDatabase(datadir, 128, 1024)
	if err != nil {
		log.Error("Can't create new DB", "error", err)
		return nil
	}
	itemCacheLimit := defaultCacheLimit
	if cacheLimit > 0 {
		itemCacheLimit = cacheLimit
	}

	cacheItems, _ := lru.New(itemCacheLimit)

	batchDB := &BatchDatabase{
		db:           db,
		cacheItems:   cacheItems,
		emptyKey:     EmptyKey(), // pre alloc for comparison
		dryRunCaches: make(map[common.Hash]*lru.Cache),
		cacheLimit:   itemCacheLimit,
	}

	return batchDB

}

func (db *BatchDatabase) IsEmptyKey(key []byte) bool {
	return key == nil || len(key) == 0 || bytes.Equal(key, db.emptyKey)
}

func (db *BatchDatabase) getCacheKey(key []byte) string {
	return hex.EncodeToString(key)
}

func (db *BatchDatabase) Has(key []byte, dryrun bool, blockHash common.Hash) (bool, error) {
	if db.IsEmptyKey(key) {
		return false, nil
	}
	cacheKey := db.getCacheKey(key)

	if dryrun {
		db.lock.Lock()
		dryrunCache, ok := db.dryRunCaches[blockHash]
		db.lock.Unlock()
		if ok && dryrunCache.Len() > 0 {
			if val, ok := dryrunCache.Get(cacheKey); ok {
				if val == nil {
					return false, nil
				}
				return true, nil
			}
		}
	} else if db.cacheItems.Contains(cacheKey) {
		// for dry-run mode, do not read cacheItems
		return true, nil
	}

	return db.db.Has(key)
}

func (db *BatchDatabase) Get(key []byte, val interface{}, dryrun bool, blockHash common.Hash) (interface{}, error) {

	if db.IsEmptyKey(key) {
		return nil, nil
	}

	cacheKey := db.getCacheKey(key)
	if dryrun {
		db.lock.Lock()
		dryrunCache, ok := db.dryRunCaches[blockHash]
		db.lock.Unlock()
		if ok && dryrunCache.Len() > 0 {
			if value, ok := dryrunCache.Get(cacheKey); ok {
				return value, nil
			}
		}
	}

	// for dry-run mode, do not read cacheItems
	if cached, ok := db.cacheItems.Get(cacheKey); ok && !dryrun {
		val = cached
	} else {

		// we can use lru for retrieving cache item, by default leveldb support get data from cache
		// but it is raw bytes
		b, err := db.db.Get(key)
		if err != nil {
			log.Debug("Key not found", "key", hex.EncodeToString(key), "err", err)
			return nil, err
		}

		err = DecodeBytesItem(b, val)

		// has problem here
		if err != nil {
			return nil, err
		}

		// update cache when reading
		if !dryrun {
			db.cacheItems.Add(cacheKey, val)
		}

	}

	return val, nil
}

func (db *BatchDatabase) Put(key []byte, val interface{}, dryrun bool, blockHash common.Hash) error {
	cacheKey := db.getCacheKey(key)
	if dryrun {
		db.lock.Lock()
		dryrunCache, ok := db.dryRunCaches[blockHash]
		db.lock.Unlock()
		if !ok {
			log.Debug("BatchDB - Put: DryrunCache of this block is not initialized. Initialize now!", "blockHash", blockHash)
			db.InitDryRunMode(blockHash, common.Hash{})
			db.lock.Lock()
			dryrunCache, _ = db.dryRunCaches[blockHash]
			db.lock.Unlock()
		}
		dryrunCache.Add(cacheKey, val)
		return nil
	}

	db.cacheItems.Add(cacheKey, val)
	value, err := EncodeBytesItem(val)
	if err != nil {
		return err
	}
	return db.db.Put(key, value)
}

func (db *BatchDatabase) Delete(key []byte, dryrun bool, blockHash common.Hash) error {
	// by default, we force delete both db and cache,
	// for better performance, we can mark a Deleted flag, to do batch delete
	cacheKey := db.getCacheKey(key)

	//mark it to nil in dryrun cache
	if dryrun {
		db.lock.Lock()
		dryrunCache, ok := db.dryRunCaches[blockHash]
		db.lock.Unlock()
		if !ok {
			log.Debug("BatchDB - Delete: DryrunCache of this block is not initialized. Initialize now!", "blockHash", blockHash)
			db.InitDryRunMode(blockHash, common.Hash{})
			db.lock.Lock()
			dryrunCache, _ = db.dryRunCaches[blockHash]
			db.lock.Unlock()
		}
		dryrunCache.Add(cacheKey, nil)
		return nil
	}

	db.cacheItems.Remove(cacheKey)
	return db.db.Delete(key)
}

func (db *BatchDatabase) InitDryRunMode(blockHashNoValidator, parentHashNoValidator common.Hash) {
	log.Debug("Start dry-run mode, clear old data", "blockhash", blockHashNoValidator, "parent", parentHashNoValidator)
	db.lock.Lock()
	dryrunCache, ok := db.dryRunCaches[blockHashNoValidator]
	db.lock.Unlock()

	// if the dryrunCache of this blockHash already existed, purge it
	// otherwise, initialize new cache for it
	// then copy all changes from parent cache
	// Finally, assign the cache to db.dryRunCaches
	if ok && dryrunCache != nil {
		dryrunCache.Purge()
	} else {
		dryrunCache, _ = lru.New(db.cacheLimit)
	}
	if parentHashNoValidator != (common.Hash{}) {
		db.lock.Lock()
		// copy all changes from parent
		parentCache, ok := db.dryRunCaches[parentHashNoValidator]
		db.lock.Unlock()
		if ok && parentCache.Len() > 0 {
			for _, cacheKey := range parentCache.Keys() {
				val, ok := parentCache.Get(cacheKey)
				if ok {
					if val != nil && reflect.ValueOf(val).Kind() == reflect.Ptr {
						// val may be pointer, should not copy a pointer
						// encode/decode to clone values
						encoded, _ := EncodeBytesItem(val)
						switch val.(type) {
						case *Item:
							value := &Item{}
							DecodeBytesItem(encoded, value)
							dryrunCache.Add(cacheKey, value)
							break
						case *OrderItem:
							value := &OrderItem{}
							DecodeBytesItem(encoded, value)
							dryrunCache.Add(cacheKey, value)
							break
						case *OrderListItem:
							value := &OrderListItem{}
							DecodeBytesItem(encoded, value)
							dryrunCache.Add(cacheKey, value)
							break
						case *OrderTreeItem:
							value := &OrderTreeItem{}
							DecodeBytesItem(encoded, value)
							dryrunCache.Add(cacheKey, value)
							break
						case *OrderBookItem:
							value := &OrderBookItem{}
							DecodeBytesItem(encoded, value)
							dryrunCache.Add(cacheKey, value)
							break
						}
					} else {
						dryrunCache.Add(cacheKey, val)
					}

				}
			}
		}
	}
	db.lock.Lock()
	db.dryRunCaches[blockHashNoValidator] = dryrunCache
	db.lock.Unlock()
}

func (db *BatchDatabase) SaveDryRunResult(blockHash common.Hash) error {
	log.Debug("Start saving dry-run result to DB ", "blockhash", blockHash)
	defer func() {
		db.lock.Lock()
		delete(db.dryRunCaches, blockHash)
		db.lock.Unlock()
	}()
	db.lock.Lock()
	dryrunCache, ok := db.dryRunCaches[blockHash]
	db.lock.Unlock()
	if !ok || dryrunCache.Len() == 0 {
		log.Debug("Nothing to SaveDryRunResult. DryrunCache is empty.", "blockhash", blockHash)
		return nil
	}
	batch := db.db.NewBatch()
	for _, cacheKey := range dryrunCache.Keys() {
		key, err := hex.DecodeString(cacheKey.(string))
		if err != nil {
			log.Error("Can't save dry-run result (hex.DecodeString)", "err", err)
			return err
		}
		val, ok := dryrunCache.Get(cacheKey)
		if !ok {
			err := errors.New("can't get item from dryrun cache")
			log.Error("Can't save dry-run result (db.dryRunCache.Get)", "err", err)
			return err
		}
		if val == nil {
			if err := db.db.Delete(key); err != nil {
				log.Error("Can't save dry-run result (db.db.Delete)", "err", err)
				return err
			}
			continue
		}

		value, err := EncodeBytesItem(val)
		if err != nil {
			log.Error("Can't save dry-run result (EncodeBytesItem)", "err", err)
			return err
		}

		if err := batch.Put(key, value); err != nil {
			log.Error("Can't save dry-run result (batch.Put)", "err", err)
			return err
		}
	}
	log.Debug("Successfully saved dry-run result to DB ", "blockhash", blockHash)
	// purge reading cache to refresh data from db
	db.cacheItems.Purge()
	return batch.Write()
}

func (db *BatchDatabase) HasDryrunCache(blockhash common.Hash) bool {
	db.lock.Lock()
	cache, ok := db.dryRunCaches[blockhash]
	db.lock.Unlock()
	if ok && cache.Len() > 0 {
		return true
	}
	return false
}

func (db *BatchDatabase) DropDryrunCache(blockhash common.Hash) {
	db.lock.Lock()
	cache, ok := db.dryRunCaches[blockhash]
	delete(db.dryRunCaches, blockhash)
	db.lock.Unlock()
	if ok && cache != nil {
		cache.Purge()
	}
}

func (db *BatchDatabase) DeleteTxMatchByTxHash(txhash common.Hash) error {
	return nil
}
