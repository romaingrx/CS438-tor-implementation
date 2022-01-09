package impl

import (
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
)

// NewPeer creates a new peer. You can change the content and location of this
// function but you MUST NOT change its signature and package location.
func NewPeer(conf peer.Configuration) peer.Peer {
	// here you must return a struct that implements the peer.Peer functions.
	// Therefore, you are free to rename and change it as you want.
	return &node{}
}

// node implements a peer to build a Peerster system
//
// - implements peer.Peer
type node struct {
	peer.Peer
	// You probably want to keep the peer.Configuration on this struct:
	//conf peer.Configuration
}

// Start implements peer.Service
func (n *node) Start() error {
	panic("to be implemented in HW0")
}

// Stop implements peer.Service
func (n *node) Stop() error {
	panic("to be implemented in HW0")
}

// Unicast implements peer.Messaging
func (n *node) Unicast(dest string, msg transport.Message) error {
	panic("to be implemented in HW0")
}

// AddPeer implements peer.Service
func (n *node) AddPeer(addr ...string) {
	panic("to be implemented in HW0")
}

// GetRoutingTable implements peer.Service
func (n *node) GetRoutingTable() peer.RoutingTable {
	panic("to be implemented in HW0")
}

// SetRoutingEntry implements peer.Service
func (n *node) SetRoutingEntry(origin, relayAddr string) {
	panic("to be implemented in HW0")
}
