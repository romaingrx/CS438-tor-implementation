package peer

type Onion interface {
	CreateRandomCircuit() error
	StringCircuits() string
}
