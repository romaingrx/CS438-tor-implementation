package types

import "fmt"

// RelayMetricRequestMessage

// NewEmpty implements types.Message.
func (c RelayMetricRequestMessage) NewEmpty() Message {
	return &RelayMetricRequestMessage{}
}

// Name implements types.Message.
func (RelayMetricRequestMessage) Name() string {
	return "relaymetricreq"
}

// String implements types.Message.
func (c RelayMetricRequestMessage) String() string {
	return fmt.Sprintf("<%s>", c.CircuitId)
}

// HTML implements types.Message.
func (c RelayMetricRequestMessage) HTML() string {
	return c.String()
}

// RelayMetricResponseMessage

// NewEmpty implements types.Message.
func (c RelayMetricResponseMessage) NewEmpty() Message {
	return &RelayMetricResponseMessage{}
}

// Name implements types.Message.
func (RelayMetricResponseMessage) Name() string {
	return "relaymetricresp"
}

// String implements types.Message.
func (c RelayMetricResponseMessage) String() string {
	return fmt.Sprintf("<%s>", c.CircuitId)
}

// HTML implements types.Message.
func (c RelayMetricResponseMessage) HTML() string {
	return c.String()
}

// RelayDataRequestMessage

// NewEmpty implements types.Message.
func (c RelayDataRequestMessage) NewEmpty() Message {
	return &RelayDataRequestMessage{}
}

// Name implements types.Message.
func (RelayDataRequestMessage) Name() string {
	return "relaydatareq"
}

// String implements types.Message.
func (c RelayDataRequestMessage) String() string {
	return fmt.Sprintf("<%s>", c.CircuitId)
}

// HTML implements types.Message.
func (c RelayDataRequestMessage) HTML() string {
	return c.String()
}

// RelayDataResponseMessage

// NewEmpty implements types.Message.
func (c RelayDataResponseMessage) NewEmpty() Message {
	return &RelayDataResponseMessage{}
}

// Name implements types.Message.
func (RelayDataResponseMessage) Name() string {
	return "relaydataresp"
}

// String implements types.Message.
func (c RelayDataResponseMessage) String() string {
	return fmt.Sprintf("<%s>", c.CircuitId)
}

// HTML implements types.Message.
func (c RelayDataResponseMessage) HTML() string {
	return c.String()
}

// KeyExchangeRequestMessage

// NewEmpty implements types.Message.
func (c KeyExchangeRequestMessage) NewEmpty() Message {
	return &KeyExchangeRequestMessage{}
}

// Name implements types.Message.
func (KeyExchangeRequestMessage) Name() string {
	return "keyexchangerequest"
}

// String implements types.Message.
func (c KeyExchangeRequestMessage) String() string {
	return c.Name()
}

// HTML implements types.Message.
func (c KeyExchangeRequestMessage) HTML() string {
	return c.String()
}

// KeyExchangeResponseMessage

// NewEmpty implements types.Message.
func (c KeyExchangeResponseMessage) NewEmpty() Message {
	return &KeyExchangeResponseMessage{}
}

// Name implements types.Message.
func (KeyExchangeResponseMessage) Name() string {
	return "keyexchangeresponse"
}

// String implements types.Message.
func (c KeyExchangeResponseMessage) String() string {
	return c.Name()
}

// HTML implements types.Message.
func (c KeyExchangeResponseMessage) HTML() string {
	return c.String()
}

// OnionLayerMessage

// NewEmpty implements types.Message.
func (c OnionLayerMessage) NewEmpty() Message {
	return &OnionLayerMessage{}
}

// Name implements types.Message.
func (OnionLayerMessage) Name() string {
	return "onionlayer"
}

// String implements types.Message.
func (c OnionLayerMessage) String() string {
	return fmt.Sprintf("<%s:%s>", c.CircuitId, c.Type)
}

// HTML implements types.Message.
func (c OnionLayerMessage) HTML() string {
	return c.String()
}

// NodeInfoMessage

// NewEmpty implements types.Message.
func (c NodeInfoMessage) NewEmpty() Message {
	return &NodeInfoMessage{}
}

// Name implements types.Message.
func (NodeInfoMessage) Name() string {
	return "nodeinfo"
}

// String implements types.Message.
func (c NodeInfoMessage) String() string {
	return fmt.Sprintf("<%s:request=%s>", c.IP, c.Request)
}

// HTML implements types.Message.
func (c NodeInfoMessage) HTML() string {
	return c.String()
}
