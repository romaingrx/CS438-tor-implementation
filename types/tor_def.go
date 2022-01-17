package types

import (
	"crypto/rsa"
	"time"
)

type RelayHttpRequest struct {
	UID               string
	DestinationIp     string
	DestinationPort   string
	RequestType       string
	Data              []byte
	ResponseData      string
	ResponseReceived  bool
	Active            bool
	SentTimeStamp     time.Time
	ReceivedTimeStamp time.Time
	Notify            chan struct{}
}

type RelayMetricRequestMessage struct {
	CircuitId string
	Payload   []byte
}
type RelayMetricBody struct {
	UID string
}

type RelayMetricResponseMessage struct {
	CircuitId string
	Payload   []byte
}

type RelayDataRequestMessage struct {
	CircuitId string
	Payload   []byte
}

type RelayDataRequestBody struct {
	UID             string
	DestinationIp   string
	DestinationPort string
	RequestType     string
	Data            []byte
}

type RelayDataResponseMessage struct {
	CircuitId string
	Payload   []byte
}

type RelayDataResponseBody struct {
	UID  string
	Data []byte
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

type NodeInfoMessage struct {
	IP        string
	PublicKey *rsa.PublicKey
	Request   bool
}
