package misc

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"io/ioutil"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ontio/ontology-crypto/signature"
	"github.com/zouxyan/eth-contracts/go_abi/eccm_abi"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/polynetwork/bsc-relayer/tools"
	"github.com/polynetwork/eth-contracts/go_abi/eccd_abi"
	polySDK "github.com/polynetwork/poly-go-sdk"
	sdkcom "github.com/polynetwork/poly-go-sdk/common"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/consensus/vbft"
	vconfig "github.com/polynetwork/poly/consensus/vbft/config"
	polytypes "github.com/polynetwork/poly/core/types"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"github.com/urfave/cli"
)

// PolyCmd ...
var PolyCmd = cli.Command{
	Name:  "poly",
	Usage: "poly actions",
	Subcommands: []cli.Command{
		polyDumpBlockConsensusCmd,
		polyCrossEthCmd,
		polyCrossBscCmd,
		polyDumpTxCmd,
		polyReverseTxHashCmd,
		polyLatestBlockMsgSnapCmd,
	},
}

var polyReverseTxHashCmd = cli.Command{
	Name:   "rev_tx",
	Usage:  "reverse tx hash",
	Action: polyReverseTx,
	Flags: []cli.Flag{
		TxFlag},
}

var polyDumpTxCmd = cli.Command{
	Name:   "dump_tx",
	Usage:  "dump tx",
	Action: polyDumpTx,
	Flags: []cli.Flag{
		TxFlag,
		NodeRPCFlag},
}

var polyLatestBlockMsgSnapCmd = cli.Command{
	Name:   "block_msg_snap",
	Usage:  "block_msg_snap",
	Action: polyLatestBlockMsgSnap,
	Flags: []cli.Flag{
		NodeRPCsFlag},
}

var polyDumpBlockConsensusCmd = cli.Command{
	Name:   "dump_block_consensus",
	Usage:  "dump block consensus",
	Action: polyDumpBlockConsensus,
	Flags: []cli.Flag{
		HeightFlag,
		NodeRPCFlag},
}

var polyCrossBscCmd = cli.Command{
	Name:   "poly_bsc",
	Usage:  "relay from poly to bsc",
	Action: polyCrossBsc,
	Flags: []cli.Flag{
		PolyConfigFlag,
		TxFlag},
}

var polyCrossEthCmd = cli.Command{
	Name:   "poly_eth",
	Usage:  "relay from poly to eth",
	Action: polyCrossEth,
	Flags: []cli.Flag{
		PolyConfigFlag,
		TxFlag},
}

// PolyConfig ...
type PolyConfig struct {
	RestURL                 string
	EntranceContractAddress string
	WalletFile              string
	WalletPwd               string
}

// BSCConfig ...
type BSCConfig struct {
	SideChainID         uint64 `json:"SideChainId"`
	RestURL             string
	ECCMContractAddress string
	ECCDContractAddress string
	KeyStorePath        string
	KeyStorePwdSet      map[string]string
}

// EthConfig ...
type EthConfig struct {
	SideChainID         uint64 `json:"SideChainId"`
	RestURL             string
	ECCMContractAddress string
	ECCDContractAddress string
	KeyStorePath        string
	KeyStorePwdSet      map[string]string
}

type polyServiceConfig struct {
	PolyConfig *PolyConfig
	BSCConfig  *BSCConfig
	EthConfig  *EthConfig
}

func newPolyServiceConfig(configFilePath string) *polyServiceConfig {
	fileContent, err := ioutil.ReadFile(configFilePath)
	if err != nil {
		panic(fmt.Sprintf("NewServiceConfig: failed, err: %s", err))
	}
	servConfig := &polyServiceConfig{}
	err = json.Unmarshal(fileContent, servConfig)
	if err != nil {
		panic(fmt.Sprintf("NewServiceConfig: failed, err: %s", err))
	}

	for k, v := range servConfig.BSCConfig.KeyStorePwdSet {
		delete(servConfig.BSCConfig.KeyStorePwdSet, k)
		servConfig.BSCConfig.KeyStorePwdSet[strings.ToLower(k)] = v
	}

	return servConfig
}

func parsePolyServiceConfig(ctx *cli.Context) (config *polyServiceConfig) {
	configFilePath := ctx.String(PolyConfigFlag.Name)
	return newPolyServiceConfig(configFilePath)
}

func jsonRequest(url string, data []byte) (result []byte, err error) {
	resp, err := http.Post(url, "application/json", strings.NewReader(string(data)))
	if err != nil {
		return
	}

	defer resp.Body.Close()

	return ioutil.ReadAll(resp.Body)
}

type polyEthTxInfo struct {
	txData       []byte
	gasLimit     uint64
	gasPrice     *big.Int
	contractAddr ethcommon.Address
	polyTxHash   string
}

func polyCrossEth(ctx *cli.Context) (err error) {
	config := parsePolyServiceConfig(ctx)

	txHash := ctx.String(TxFlag.Name)

	sdk := polySDK.NewPolySdk()
	client := sdk.NewRpcClient()
	client.SetAddress(config.PolyConfig.RestURL)

	contractAbi, err := abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	if err != nil {
		return
	}

	ethereumsdk, err := ethclient.Dial(config.EthConfig.RestURL)
	if err != nil {
		return
	}

	chainID, err := ethereumsdk.ChainID(context.Background())
	if err != nil {
		return
	}

	ks := NewEthKeyStore(config.EthConfig.KeyStorePath, config.EthConfig.KeyStorePwdSet, chainID)
	accounts := ks.GetAccounts()
	account := accounts[rand.Intn(len(accounts))]

	nonceManager := tools.NewNonceManager(ethereumsdk)

	event, err := sdk.GetSmartContractEvent(txHash)
	if err != nil {
		return
	}

	height, err := sdk.GetBlockHeightByTxHash(txHash)
	if err != nil {
		return
	}

	eccdAddr := ethcommon.HexToAddress(config.EthConfig.ECCDContractAddress)
	eccd, err := eccd_abi.NewEthCrossChainData(eccdAddr, ethereumsdk)
	if err != nil {
		return
	}

	epochStartHeight, err := eccd.GetCurEpochStartHeight(nil)
	if err != nil {
		return
	}

	nextHeader, err := sdk.GetHeaderByHeight(height + 1)
	if err != nil {
		return
	}

	var (
		anchor *polytypes.Header
		hp     string
	)

	if epochStartHeight >= nextHeader.Height {
		anchor, _ = sdk.GetHeaderByHeight(epochStartHeight + 1)
		proof, _ := sdk.GetMerkleProof(nextHeader.Height, anchor.Height)
		hp = proof.AuditPath
	} else if (nextHeader.NextBookkeeper != common.Address{}) {
		anchor, _ = sdk.GetHeaderByHeight(nextHeader.Height + 1)
		proof, _ := sdk.GetMerkleProof(nextHeader.Height, anchor.Height)
		hp = proof.AuditPath
	}

	waitTransactionConfirm := func(polyTxHash string, hash ethcommon.Hash) bool {
		for {
			time.Sleep(time.Second * 1)
			_, ispending, err := ethereumsdk.TransactionByHash(context.Background(), hash)
			if err != nil {
				continue
			}
			log.Printf("( eth_transaction %s, poly_tx %s ) is pending: %v", hash.String(), polyTxHash, ispending)
			if ispending == true {
				continue
			} else {
				receipt, err := ethereumsdk.TransactionReceipt(context.Background(), hash)
				if err != nil {
					continue
				}
				return receipt.Status == types.ReceiptStatusSuccessful
			}
		}
	}

	sendTxToEth := func(info *polyEthTxInfo) error {
		nonce := nonceManager.GetAddressNonce(account.Address)
		tx := types.NewTransaction(nonce, info.contractAddr, big.NewInt(0), info.gasLimit, info.gasPrice, info.txData)
		signedtx, err := ks.SignTransaction(tx, account)
		if err != nil {
			nonceManager.ReturnNonce(account.Address, nonce)
			return fmt.Errorf("commitDepositEventsWithHeader - sign raw tx error and return nonce %d: %v", nonce, err)
		}
		err = ethereumsdk.SendTransaction(context.Background(), signedtx)
		if err != nil {
			nonceManager.ReturnNonce(account.Address, nonce)
			return fmt.Errorf("commitDepositEventsWithHeader - send transaction error and return nonce %d: %v", nonce, err)
		}
		hash := signedtx.Hash()

		isSuccess := waitTransactionConfirm(info.polyTxHash, hash)
		if isSuccess {
			log.Printf("successful to relay tx to ethereum: (eth_hash: %s, nonce: %d, poly_hash: %s, eth_explorer: %s)",
				hash.String(), nonce, info.polyTxHash, tools.GetExplorerUrl(ks.GetChainId())+hash.String())
		} else {
			log.Printf("failed to relay tx to ethereum: (eth_hash: %s, nonce: %d, poly_hash: %s, eth_explorer: %s)",
				hash.String(), nonce, info.polyTxHash, tools.GetExplorerUrl(ks.GetChainId())+hash.String())
		}
		return nil
	}
	commitDepositEventsWithHeader := func(header *polytypes.Header, param *common2.ToMerkleValue, headerProof string, anchorHeader *polytypes.Header, polyTxHash string, rawAuditPath []byte) (err error) {
		var (
			sigs       []byte
			headerData []byte
		)
		if anchorHeader != nil && headerProof != "" {
			for _, sig := range anchorHeader.SigData {
				temp := make([]byte, len(sig))
				copy(temp, sig)
				newsig, _ := signature.ConvertToEthCompatible(temp)
				sigs = append(sigs, newsig...)
			}
		} else {
			for _, sig := range header.SigData {
				temp := make([]byte, len(sig))
				copy(temp, sig)
				newsig, _ := signature.ConvertToEthCompatible(temp)
				sigs = append(sigs, newsig...)
			}
		}

		fromTx := [32]byte{}
		copy(fromTx[:], param.TxHash[:32])
		res, _ := eccd.CheckIfFromChainTxExist(nil, param.FromChainID, fromTx)
		if res {
			log.Printf("already relayed to eth: ( from_chain_id: %d, from_txhash: %x,  param.Txhash: %x)",
				param.FromChainID, param.TxHash, param.MakeTxParam.TxHash)
			return
		}
		//log.Infof("poly proof with header, height: %d, key: %s, proof: %s", header.Height-1, string(key), proof.AuditPath)

		rawProof, _ := hex.DecodeString(headerProof)
		var rawAnchor []byte
		if anchorHeader != nil {
			rawAnchor = anchorHeader.GetMessage()
		}
		headerData = header.GetMessage()
		txData, err := contractAbi.Pack("verifyHeaderAndExecuteTx", rawAuditPath, headerData, rawProof, rawAnchor, sigs)
		if err != nil {
			log.Printf("commitDepositEventsWithHeader - err:" + err.Error())
			return
		}

		gasPrice, err := ethereumsdk.SuggestGasPrice(context.Background())
		if err != nil {
			log.Printf("commitDepositEventsWithHeader - get suggest sas price failed error: %s", err.Error())
			return
		}
		contractaddr := ethcommon.HexToAddress(config.BSCConfig.ECCMContractAddress)
		callMsg := ethereum.CallMsg{
			From: account.Address, To: &contractaddr, Gas: 0, GasPrice: gasPrice,
			Value: big.NewInt(0), Data: txData,
		}
		gasLimit, err := ethereumsdk.EstimateGas(context.Background(), callMsg)
		if err != nil {
			log.Printf("commitDepositEventsWithHeader - estimate gas limit error: %s", err.Error())
			return
		}

		info := &polyEthTxInfo{
			txData:       txData,
			contractAddr: contractaddr,
			gasPrice:     gasPrice,
			gasLimit:     gasLimit,
			polyTxHash:   polyTxHash,
		}
		err = sendTxToEth(info)
		return
	}

	var proof *sdkcom.MerkleProof
	for _, notify := range event.Notify {
		if notify.ContractAddress == "0300000000000000000000000000000000000000" {
			states := notify.States.([]interface{})
			method, _ := states[0].(string)
			if method != "makeProof" {
				continue
			}
			if uint64(states[2].(float64)) != config.EthConfig.SideChainID {
				err = fmt.Errorf("SideChainId not match:%d", int(states[2].(float64)))
				return
			}

			proof, err = sdk.GetCrossStatesProof(height, states[5].(string))
			if err != nil {
				return
			}

			auditpath, _ := hex.DecodeString(proof.AuditPath)
			value, _, _, _ := tools.ParseAuditpath(auditpath)
			param := &common2.ToMerkleValue{}
			if err = param.Deserialization(common.NewZeroCopySource(value)); err != nil {
				return
			}

			err = commitDepositEventsWithHeader(nextHeader, param, hp, anchor, event.TxHash, auditpath)
			if err != nil {
				return
			}
		}
	}

	return
}

func polyCrossBsc(ctx *cli.Context) (err error) {

	config := parsePolyServiceConfig(ctx)

	txHash := ctx.String(TxFlag.Name)

	sdk := polySDK.NewPolySdk()
	client := sdk.NewRpcClient()
	client.SetAddress(config.PolyConfig.RestURL)

	contractAbi, err := abi.JSON(strings.NewReader(eccm_abi.EthCrossChainManagerABI))
	if err != nil {
		return
	}

	ethereumsdk, err := ethclient.Dial(config.BSCConfig.RestURL)
	if err != nil {
		return
	}

	chainID, err := ethereumsdk.ChainID(context.Background())
	if err != nil {
		return
	}
	ks := NewEthKeyStore(config.BSCConfig.KeyStorePath, config.BSCConfig.KeyStorePwdSet, chainID)
	accounts := ks.GetAccounts()
	account := accounts[rand.Intn(len(accounts))]

	nonceManager := tools.NewNonceManager(ethereumsdk)

	event, err := sdk.GetSmartContractEvent(txHash)
	if err != nil {
		return
	}

	height, err := sdk.GetBlockHeightByTxHash(txHash)
	if err != nil {
		return
	}

	eccdAddr := ethcommon.HexToAddress(config.BSCConfig.ECCDContractAddress)
	eccd, err := eccd_abi.NewEthCrossChainData(eccdAddr, ethereumsdk)
	if err != nil {
		return
	}

	epochStartHeight, err := eccd.GetCurEpochStartHeight(nil)
	if err != nil {
		return
	}

	nextHeader, err := sdk.GetHeaderByHeight(height + 1)
	if err != nil {
		return
	}

	var (
		anchor *polytypes.Header
		hp     string
	)

	if epochStartHeight >= nextHeader.Height {
		anchor, _ = sdk.GetHeaderByHeight(epochStartHeight + 1)
		proof, _ := sdk.GetMerkleProof(nextHeader.Height, anchor.Height)
		hp = proof.AuditPath
	} else if (nextHeader.NextBookkeeper != common.Address{}) {
		anchor, _ = sdk.GetHeaderByHeight(nextHeader.Height + 1)
		proof, _ := sdk.GetMerkleProof(nextHeader.Height, anchor.Height)
		hp = proof.AuditPath
	}

	waitTransactionConfirm := func(polyTxHash string, hash ethcommon.Hash) bool {
		for {
			time.Sleep(time.Second * 1)
			_, ispending, err := ethereumsdk.TransactionByHash(context.Background(), hash)
			if err != nil {
				continue
			}
			log.Printf("( bsc_transaction %s, poly_tx %s ) is pending: %v", hash.String(), polyTxHash, ispending)
			if ispending == true {
				continue
			} else {
				receipt, err := ethereumsdk.TransactionReceipt(context.Background(), hash)
				if err != nil {
					continue
				}
				return receipt.Status == types.ReceiptStatusSuccessful
			}
		}
	}

	sendTxToEth := func(info *polyEthTxInfo) error {
		nonce := nonceManager.GetAddressNonce(account.Address)
		tx := types.NewTransaction(nonce, info.contractAddr, big.NewInt(0), info.gasLimit, info.gasPrice, info.txData)
		signedtx, err := ks.SignTransaction(tx, account)
		if err != nil {
			nonceManager.ReturnNonce(account.Address, nonce)
			return fmt.Errorf("commitDepositEventsWithHeader - sign raw tx error and return nonce %d: %v", nonce, err)
		}
		err = ethereumsdk.SendTransaction(context.Background(), signedtx)
		if err != nil {
			nonceManager.ReturnNonce(account.Address, nonce)
			return fmt.Errorf("commitDepositEventsWithHeader - send transaction error and return nonce %d: %v", nonce, err)
		}
		hash := signedtx.Hash()

		isSuccess := waitTransactionConfirm(info.polyTxHash, hash)
		if isSuccess {
			log.Printf("successful to relay tx to ethereum: (eth_hash: %s, nonce: %d, poly_hash: %s, eth_explorer: %s)",
				hash.String(), nonce, info.polyTxHash, tools.GetExplorerUrl(ks.GetChainId())+hash.String())
		} else {
			log.Printf("failed to relay tx to ethereum: (eth_hash: %s, nonce: %d, poly_hash: %s, eth_explorer: %s)",
				hash.String(), nonce, info.polyTxHash, tools.GetExplorerUrl(ks.GetChainId())+hash.String())
		}
		return nil
	}
	commitDepositEventsWithHeader := func(header *polytypes.Header, param *common2.ToMerkleValue, headerProof string, anchorHeader *polytypes.Header, polyTxHash string, rawAuditPath []byte) (err error) {
		var (
			sigs       []byte
			headerData []byte
		)
		if anchorHeader != nil && headerProof != "" {
			for _, sig := range anchorHeader.SigData {
				temp := make([]byte, len(sig))
				copy(temp, sig)
				newsig, _ := signature.ConvertToEthCompatible(temp)
				sigs = append(sigs, newsig...)
			}
		} else {
			for _, sig := range header.SigData {
				temp := make([]byte, len(sig))
				copy(temp, sig)
				newsig, _ := signature.ConvertToEthCompatible(temp)
				sigs = append(sigs, newsig...)
			}
		}

		fromTx := [32]byte{}
		copy(fromTx[:], param.TxHash[:32])
		res, _ := eccd.CheckIfFromChainTxExist(nil, param.FromChainID, fromTx)
		if res {
			log.Printf("already relayed to eth: ( from_chain_id: %d, from_txhash: %x,  param.Txhash: %x)",
				param.FromChainID, param.TxHash, param.MakeTxParam.TxHash)
			return
		}
		//log.Infof("poly proof with header, height: %d, key: %s, proof: %s", header.Height-1, string(key), proof.AuditPath)

		rawProof, _ := hex.DecodeString(headerProof)
		var rawAnchor []byte
		if anchorHeader != nil {
			rawAnchor = anchorHeader.GetMessage()
		}
		headerData = header.GetMessage()
		txData, err := contractAbi.Pack("verifyHeaderAndExecuteTx", rawAuditPath, headerData, rawProof, rawAnchor, sigs)
		if err != nil {
			log.Printf("commitDepositEventsWithHeader - err:" + err.Error())
			return
		}

		gasPrice, err := ethereumsdk.SuggestGasPrice(context.Background())
		if err != nil {
			log.Printf("commitDepositEventsWithHeader - get suggest sas price failed error: %s", err.Error())
			return
		}
		contractaddr := ethcommon.HexToAddress(config.BSCConfig.ECCMContractAddress)
		callMsg := ethereum.CallMsg{
			From: account.Address, To: &contractaddr, Gas: 0, GasPrice: gasPrice,
			Value: big.NewInt(0), Data: txData,
		}
		gasLimit, err := ethereumsdk.EstimateGas(context.Background(), callMsg)
		if err != nil {
			log.Printf("commitDepositEventsWithHeader - estimate gas limit error: %s", err.Error())
			return
		}

		info := &polyEthTxInfo{
			txData:       txData,
			contractAddr: contractaddr,
			gasPrice:     gasPrice,
			gasLimit:     gasLimit,
			polyTxHash:   polyTxHash,
		}
		err = sendTxToEth(info)
		return
	}

	var proof *sdkcom.MerkleProof
	for _, notify := range event.Notify {
		if notify.ContractAddress == "0300000000000000000000000000000000000000" {
			states := notify.States.([]interface{})
			method, _ := states[0].(string)
			if method != "makeProof" {
				continue
			}
			if uint64(states[2].(float64)) != config.BSCConfig.SideChainID {
				err = fmt.Errorf("SideChainId not match:%d", int(states[2].(float64)))
				return
			}

			proof, err = sdk.GetCrossStatesProof(height, states[5].(string))
			if err != nil {
				return
			}

			auditpath, _ := hex.DecodeString(proof.AuditPath)
			value, _, _, _ := tools.ParseAuditpath(auditpath)
			param := &common2.ToMerkleValue{}
			if err = param.Deserialization(common.NewZeroCopySource(value)); err != nil {
				return
			}

			err = commitDepositEventsWithHeader(nextHeader, param, hp, anchor, event.TxHash, auditpath)
			if err != nil {
				return
			}
		}
	}

	return
}

func polyReverseTx(ctx *cli.Context) (err error) {

	txHash := ctx.String(TxFlag.Name)

	raw, err := hex.DecodeString(txHash)
	if err != nil {
		return
	}

	fmt.Println("result", hex.EncodeToString(common.ToArrayReverse(raw)))
	return
}

func polyDumpTx(ctx *cli.Context) (err error) {
	sdk := polySDK.NewPolySdk()
	client := sdk.NewRpcClient()
	client.SetAddress(ctx.String(NodeRPCFlag.Name))

	txHash := ctx.String(TxFlag.Name)

	event, err := sdk.GetSmartContractEvent(txHash)
	if err != nil {
		return
	}

	eventBytes, _ := json.Marshal(event)

	fmt.Println("event", string(eventBytes))
	return
}

func parseNodeRPCs(ctx *cli.Context) (urls []string, err error) {
	nodes := ctx.String(NodeRPCsFlag.Name)
	if nodes == "" {
		err = fmt.Errorf("empty node_rpcs not allowed")
		return
	}
	urls = strings.Split(nodes, ",")

	return
}

func polyLatestBlockMsgSnap(ctx *cli.Context) (err error) {

	nodes, err := parseNodeRPCs(ctx)
	if err != nil {
		return
	}

	paramBytes, _ := json.Marshal(map[string]interface{}{
		"method": "getlatestblockmsgssnap",
		"params": []interface{}{},
	})
	var resultBytes []byte
	for i, node := range nodes {
		resultBytes, err = jsonRequest(fmt.Sprintf("http://%s/getlatestblockmsgssnap", node), paramBytes)
		if err != nil {
			return
		}

		fmt.Printf("node %d: %s", i+1, string(resultBytes))
	}
	return
}

func polyDumpBlockConsensus(ctx *cli.Context) (err error) {

	sdk := polySDK.NewPolySdk()
	client := sdk.NewRpcClient()
	client.SetAddress(ctx.String(NodeRPCFlag.Name))

	height := uint32(ctx.Int(HeightFlag.Name))

	block, err := sdk.GetBlockByHeight(height)
	if err != nil {
		err = fmt.Errorf("GetBlockByHeight:%v", err)
		return
	}

	info := &vconfig.VbftBlockInfo{}
	err = json.Unmarshal(block.Header.ConsensusPayload, info)
	if err != nil {
		err = fmt.Errorf("Unmarshal:%v", err)
		return
	}

	if info.NewChainConfig == nil {
		var lastblock *polytypes.Block
		lastblock, err = sdk.GetBlockByHeight(info.LastConfigBlockNum)
		if err != nil {
			err = fmt.Errorf("GetBlockByHeight2:%v", err)
			return
		}

		lastInfo := &vconfig.VbftBlockInfo{}
		err = json.Unmarshal(lastblock.Header.ConsensusPayload, lastInfo)
		if err != nil {
			err = fmt.Errorf("Unmarshal2:%v", err)
			return
		}

		info.NewChainConfig = lastInfo.NewChainConfig
	}

	fmt.Println("NextBookkeeper", block.Header.NextBookkeeper.ToHexString())
	fmt.Println("Proposer", info.Proposer)
	fmt.Println("LastConfigBlockNum", info.LastConfigBlockNum)

	currentParticipantConfig, err := buildParticipantConfig(height+1, block, info)
	if err != nil {
		return
	}
	currentParticipantConfigBytes, _ := json.MarshalIndent(currentParticipantConfig, "", "\t")
	fmt.Println("currentParticipantConfig", string(currentParticipantConfigBytes))

	return
}

func buildParticipantConfig(blkNum uint32, block *polytypes.Block, vbftInfo *vconfig.VbftBlockInfo) (*vbft.BlockParticipantConfig, error) {

	if blkNum == 0 {
		return nil, fmt.Errorf("not participant config for genesis block")
	}

	vrfValue := getParticipantSelectionSeed(block, vbftInfo)
	if vrfValue.IsNil() {
		return nil, fmt.Errorf("failed to calculate participant SelectionSeed")
	}

	chainCfg := vbftInfo.NewChainConfig
	cfg := &vbft.BlockParticipantConfig{
		BlockNum:    blkNum,
		Vrf:         vrfValue,
		ChainConfig: chainCfg, // TODO: copy chain config
	}

	s := 0

	Proposers := calcParticipantPeers(cfg, chainCfg, s, s+vconfig.MAX_PROPOSER_COUNT)
	if uint32(len(Proposers)) < chainCfg.C+1 {
		return nil, fmt.Errorf("cfg Proposers length less than chainCfg.C:%d,%d", uint32(len(cfg.Proposers)), chainCfg.C)
	}
	cfg.Proposers = Proposers[:chainCfg.C+1]
	s += vconfig.MAX_PROPOSER_COUNT
	cfg.Endorsers = calcParticipantPeers(cfg, chainCfg, s, s+vconfig.MAX_ENDORSER_COUNT)
	if uint32(len(cfg.Endorsers)) < 2*chainCfg.C {
		return nil, fmt.Errorf("cfg.Endorsers length less than double chainCfg.C:%d,%d", uint32(len(cfg.Endorsers)), chainCfg.C)
	}
	s += vconfig.MAX_ENDORSER_COUNT
	cfg.Committers = calcParticipantPeers(cfg, chainCfg, s, s+vconfig.MAX_COMMITTER_COUNT)
	if uint32(len(cfg.Committers)) < 2*chainCfg.C {
		return nil, fmt.Errorf("cfg.Committers length less than double chainCfg.C:%d,%d", uint32(len(cfg.Committers)), chainCfg.C)
	}

	return cfg, nil
}

type seedData struct {
	BlockNum          uint32         `json:"block_num"`
	PrevBlockProposer uint32         `json:"prev_block_proposer"` // TODO: change to NodeID
	BlockRoot         common.Uint256 `json:"block_root"`
	VrfValue          []byte         `json:"vrf_value"`
}

func getParticipantSelectionSeed(block *polytypes.Block, vbftInfo *vconfig.VbftBlockInfo) vconfig.VRFValue {

	data, err := json.Marshal(&seedData{
		BlockNum:          block.Header.Height + 1,
		PrevBlockProposer: vbftInfo.Proposer,
		BlockRoot:         block.Header.BlockRoot,
		VrfValue:          vbftInfo.VrfValue,
	})
	if err != nil {
		return vconfig.VRFValue{}
	}

	t := sha512.Sum512(data)
	f := sha512.Sum512(t[:])
	return vconfig.VRFValue(f)
}

func checkCalcEndorserOrCommitter(end int) bool {
	if end == vconfig.MAX_ENDORSER_COUNT+vconfig.MAX_PROPOSER_COUNT ||
		end == vconfig.MAX_PROPOSER_COUNT+vconfig.MAX_ENDORSER_COUNT+vconfig.MAX_COMMITTER_COUNT {
		return true
	}
	return false
}

func calcParticipantPeers(cfg *vbft.BlockParticipantConfig, chain *vconfig.ChainConfig, start, end int) []uint32 {

	peers := make([]uint32, 0)
	peerMap := make(map[uint32]bool)
	proposerMap := make(map[uint32]bool)
	var cnt uint32

	if checkCalcEndorserOrCommitter(end) {
		if len(cfg.Proposers) != 0 {
			for _, p := range cfg.Proposers {
				proposerMap[p] = true
				if uint32(len(proposerMap)) >= chain.C {
					break
				}
			}
		}
	}
	for i := start; ; i++ {
		peerID := calcParticipant(cfg.Vrf, chain.PosTable, uint32(i))
		if peerID == math.MaxUint32 {
			return []uint32{}
		}
		if checkCalcEndorserOrCommitter(end) {
			if _, present := proposerMap[peerID]; present {
				continue
			}
		}
		if _, present := peerMap[peerID]; !present {
			// got new peer
			peers = append(peers, peerID)
			peerMap[peerID] = true
			cnt++
			if cnt >= chain.N {
				return peers
			}
		}
		if end == vconfig.MAX_PROPOSER_COUNT {
			if i >= end && uint32(len(peers)) > chain.C {
				return peers
			}
		}
		if checkCalcEndorserOrCommitter(end) {
			if uint32(len(peers)) > chain.C*2 {
				return peers
			}
		}
	}
}

func calcParticipant(vrf vconfig.VRFValue, dposTable []uint32, k uint32) uint32 {
	var v1, v2 uint32
	bIdx := k / 8
	bits1 := k % 8
	bits2 := 8 + bits1 // L - 8 + bits1
	if k >= 512 {
		return math.MaxUint32
	}
	// FIXME:
	// take 16bits random variable from vrf, if len(dposTable) is not power of 2,
	// this algorithm will break the fairness of vrf. to be fixed
	v1 = uint32(vrf[bIdx]) >> bits1
	if bIdx+1 < uint32(len(vrf)) {
		v2 = uint32(vrf[bIdx+1])
	} else {
		v2 = uint32(vrf[0])
	}

	v2 = v2 & ((1 << bits2) - 1)
	v := (v2 << (8 - bits1)) + v1
	v = v % uint32(len(dposTable))
	return dposTable[v]
}
