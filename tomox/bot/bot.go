package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/tomox"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

//
//var (
//	userAddr = common.HexToAddress("0x17F2beD710ba50Ed27aEa52fc4bD7Bda5ED4a037")
//	PK       = os.Getenv("MAIN_ADDRESS_KEY")
//)

func buildOrder(userAddr string) *tomox.OrderItem {
	var ether = big.NewInt(1000000000000000000)
	rand.Seed(time.Now().UTC().UnixNano())
	lstBuySell := []string{"BUY", "SELL"}
	tomoPrice, _ := getPrice("tomochain", "btc")
	btcPrice := int(1 / tomoPrice)
	order := &tomox.OrderItem{
		Quantity:        big.NewInt(0).Mul(big.NewInt(int64(rand.Intn(10)+1)), ether),
		Price:           big.NewInt(0).Mul(big.NewInt(int64(rand.Intn(10)+btcPrice)), ether),
		ExchangeAddress: common.HexToAddress("0x0D3ab14BBaD3D99F4203bd7a11aCB94882050E7e"),
		UserAddress:     common.HexToAddress(userAddr),
		BaseToken:       common.HexToAddress("0x4d7eA2cE949216D6b120f3AA10164173615A2b6C"),
		QuoteToken:      common.HexToAddress(common.TomoNativeAddress),
		Status:          tomox.OrderStatusNew,
		Side:            lstBuySell[rand.Int()%len(lstBuySell)],
		Type:            tomox.Limit,
		PairName:        "BTC/TOMO",
		FilledAmount:    new(big.Int).SetUint64(0),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	fmt.Printf("price %v  ", order.Price)
	return order
}

func createOrder(rpcClient *rpc.Client, userAddr, pk string) error {
	order := buildOrder(userAddr)
	order.Nonce = big.NewInt(0).Add(getOrderNonce(rpcClient, order.UserAddress), big.NewInt(1))
	order.Hash = computeHash(order)

	privKey, _ := crypto.HexToECDSA(pk)
	message := crypto.Keccak256(
		[]byte("\x19Ethereum Signed Message:\n32"),
		order.Hash.Bytes(),
	)
	signatureBytes, _ := crypto.Sign(message, privKey)
	sig := &tomox.Signature{
		R: common.BytesToHash(signatureBytes[0:32]),
		S: common.BytesToHash(signatureBytes[32:64]),
		V: signatureBytes[64] + 27,
	}
	order.Signature = sig

	topic := order.BaseToken.Hex() + "::" + order.QuoteToken.Hex()
	encodedTopic := fmt.Sprintf("0x%s", hex.EncodeToString([]byte(topic)))
	fmt.Println("nonce: ", order.Nonce.Uint64())

	var result interface{}
	params := make(map[string]interface{})
	params["topic"] = encodedTopic
	err := rpcClient.Call(&result, "tomox_newTopic", params)
	if err != nil {
		return fmt.Errorf("rpcClient.Call tomox_newTopic failed %v", err)
	}

	//create new order
	params["payload"], err = json.Marshal(order)
	if err != nil {
		return fmt.Errorf("json.Marshal failed %v", err)
	}

	err = rpcClient.Call(&result, "tomox_createOrder", params)
	if err != nil {
		return fmt.Errorf("rpcClient.Call tomox_createOrder failed %v", err)
	}
	return nil
}

func main() {
	ipaddress := "127.0.0.1"
	rpcEndpoint := fmt.Sprintf("http://%s:1545", ipaddress)
	rpcClient, err := rpc.DialHTTP(rpcEndpoint)
	defer rpcClient.Close()
	if err != nil {
		fmt.Println("rpc.DialHTTP failed", "err", err)
		os.Exit(1)
	}
	for {
		if err := createOrder(rpcClient, os.Args[1], os.Args[2]); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		time.Sleep(10 * time.Second)
	}
}

func getPrice(base, quote string) (float32, error) {
	resp, err := http.Get("https://api.coingecko.com/api/v3/simple/price?ids=" + base + "&vs_currencies=" + quote)
	if err != nil {
		return float32(0), fmt.Errorf(err.Error())
	}
	var data map[string]map[string]float32
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return float32(0), fmt.Errorf(err.Error())
	}
	return data[base][quote], nil
}

func getOrderNonce(rpcClient *rpc.Client, addr common.Address) *big.Int {
	nonce := int64(0)
	result := ""
	if err := rpcClient.Call(&result, "tomox_getOrderNonce", addr); err != nil {
		fmt.Printf("Can't get orderNonce from rpc %v", err)
	}
	nonce, _ = strconv.ParseInt(strings.TrimLeft(result, "0x"), 16, 64)
	return big.NewInt(nonce)
}

func computeHash(o *tomox.OrderItem) common.Hash {
	sha := sha3.NewKeccak256()
	sha.Write(o.ExchangeAddress.Bytes())
	sha.Write(o.UserAddress.Bytes())
	sha.Write(o.BaseToken.Bytes())
	sha.Write(o.QuoteToken.Bytes())
	sha.Write(common.BigToHash(o.Quantity).Bytes())
	if o.Price != nil {
		sha.Write(common.BigToHash(o.Price).Bytes())
	}
	if o.Side == tomox.Bid {
		sha.Write(common.BigToHash(big.NewInt(0)).Bytes())
	} else {
		sha.Write(common.BigToHash(big.NewInt(1)).Bytes())
	}
	sha.Write(common.BigToHash(o.Nonce).Bytes())
	sha.Write(common.StringToHash(o.Status).Bytes())
	sha.Write(common.StringToHash(o.Type).Bytes())
	return common.BytesToHash(sha.Sum(nil))
}
