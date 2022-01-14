package crypto

import (
	"crypto/sha256"
	"github.com/monnand/dhkx"
	"golang.org/x/xerrors"
	"reflect"
)

type DiffieHellman struct {
	group        *dhkx.DHGroup
	private, key *dhkx.DHKey
	public       []byte
}

func (dh *DiffieHellman) IsMisconfigured() bool {
	var s int
	cdts := []bool{dh.group == nil, dh.private == nil, dh.public == nil}
	for _, cdt := range cdts {
		if cdt {
			s += 1
		}
	}
	return s%len(cdts) != 0
}

func (dh *DiffieHellman) IsNotConfigured() bool {
	return dh.group == nil && !dh.IsMisconfigured()
}

func (dh *DiffieHellman) GenerateParameters() ([]byte, error) {
	group, err := dhkx.GetGroup(1)
	if err != nil {
		return nil, err
	}

	private, err := group.GeneratePrivateKey(nil)
	if err != nil {
		return nil, err
	}

	dh.group = group
	dh.private = private
	dh.public = dh.private.Bytes()
	return dh.public, err
}

func (dh *DiffieHellman) HandleNegotiation(publicKey []byte) ([]byte, error) {
	pK := dhkx.NewPublicKey(publicKey)
	if dh.IsMisconfigured() {
		return nil, xerrors.Errorf("Diffie Hellman misconfigured, can't negociate the keys")
	}
	if dh.IsNotConfigured() {
		if _, err := dh.GenerateParameters(); err != nil {
			return nil, err
		}

	}
	sharedKey, err := dh.group.ComputeKey(pK, dh.private)
	if err != nil {
		return nil, err
	}
	dh.key = sharedKey
	return dh.public, nil
}

func (dh *DiffieHellman) HandleAndVerifyNegotiation(publicKey []byte, preMasterSecret []byte) bool {
	computedPk, err := dh.HandleNegotiation(publicKey)
	return reflect.DeepEqual(computedPk, preMasterSecret) && err == nil
}

func (dh *DiffieHellman) GetMasterSecret() []byte {
	hash := sha256.Sum256(dh.key.Bytes())
	return hash[:]
}

// func main() {
// 	dha := DiffieHellman{}
// 	pka, _ := dha.GenerateParameters()
//
// 	dhb := DiffieHellman{}
// 	pkb, _ := dhb.HandleNegotiation(pka)
// 	dha.HandleNegotiation(pkb)
//
// 	plaintext := []byte("Hello big boiiiii")
// 	ciphertext, _ := Encrypt(dha.GetMasterSecret(), plaintext)
// 	recovertext, _ := Decrypt(dhb.GetMasterSecret(), ciphertext)
// 	fmt.Println(string(recovertext))
// }
