package types

type RelayMetricRequestMessage struct {
	CircuitId string
	UID       string
}

type RelayMetricResponseMessage struct {
	CircuitId string
	UID       string
}

type RelayDataRequestMessage struct {
	CircuitId       string
	UID             string
	DestinationIp   string
	DestinationPort string
	RequestType     string
	Data            []byte
}

type RelayDataResponseMessage struct {
	CircuitId string
	UID       string
	Data      []byte
}

type OnionLayerDirection bool

const (
	OnionLayerForward  OnionLayerDirection = false
	OnionLayerBackward OnionLayerDirection = true
)

type OnionLayerMessage struct {
	CircuitId string
	Cmd       string
	Direction OnionLayerDirection
	Type      string
	Payload   []byte
}

type KeyExchangeRequestMessage struct {
	CircuitId  string
	Parameters []byte
	Extend     string
}

type KeyExchangeResponseMessage struct {
	CircuitId  string
	Parameters []byte
	Signature  []byte
}
