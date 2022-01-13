package crypto


type KeyExchange interface {
	GenerateParameters() ([]byte, error)
	HandleNegociation(publicKey []byte) ([]byte, error)
	GetMasterSecret() []byte
}