package peer

import "go.dedis.ch/cs438/types"

type Onion interface {
	CreateRandomCircuit() error
	StringCircuits() string
	SendMessage(httpRequestType, destinationIp, port string, data []byte) (*types.RelayHttpRequest, error)
	StartSyncDirectoryKeys() error
	StartProxy()
	SendMetrics(string)
}
