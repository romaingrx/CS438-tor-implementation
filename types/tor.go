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
	return fmt.Sprintf("<%s:%s>", c.CircuitId, c.UID)
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
	return fmt.Sprintf("<%s:%s>", c.CircuitId, c.UID)
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
	return fmt.Sprintf("<%s:%s>", c.CircuitId, c.UID)
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
	return fmt.Sprintf("<%s:%s>", c.CircuitId, c.UID)
}

// HTML implements types.Message.
func (c RelayDataResponseMessage) HTML() string {
	return c.String()
}
