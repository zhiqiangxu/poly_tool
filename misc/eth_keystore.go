package misc

import (
	"fmt"
	"math/big"
	"strings"

	"log"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/core/types"
)

// EthKeyStore ...
type EthKeyStore struct {
	ks      *keystore.KeyStore
	chainId *big.Int
}

// NewEthKeyStore ...
func NewEthKeyStore(path string, pwdset map[string]string, chainId *big.Int) *EthKeyStore {
	service := &EthKeyStore{}
	capitalKeyStore := keystore.NewKeyStore(path, keystore.StandardScryptN,
		keystore.StandardScryptP)
	accArr := capitalKeyStore.Accounts()
	if len(accArr) == 0 {
		panic("no account found")
	}
	str := ""
	for i, v := range accArr {
		str += fmt.Sprintf("(no.%d acc: %s), ", i+1, v.Address.String())
	}
	log.Printf("using accounts: [ %s ]", str)
	service.ks = capitalKeyStore
	service.chainId = chainId

	err := service.unlockKeys(pwdset)
	if err != nil {
		panic(fmt.Errorf("unlockKeys failed:%v", err))
	}
	return service
}

func (this *EthKeyStore) unlockKeys(pwdset map[string]string) error {
	for _, v := range this.GetAccounts() {
		err := this.ks.Unlock(v, pwdset[strings.ToLower(v.Address.String())])
		if err != nil {
			return fmt.Errorf("failed to unlock acc %s: %v", v.Address.String(), err)
		}
	}
	return nil
}

func (this *EthKeyStore) SignTransaction(tx *types.Transaction, acc accounts.Account) (*types.Transaction, error) {
	tx, err := this.ks.SignTx(acc, tx, this.chainId)
	if err != nil {
		return nil, err
	}
	return tx, nil
}

func (this *EthKeyStore) GetAccounts() []accounts.Account {
	return this.ks.Accounts()
}

func (this *EthKeyStore) GetChainId() uint64 {
	return this.chainId.Uint64()
}
