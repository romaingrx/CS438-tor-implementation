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
