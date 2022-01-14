package impl

import (
	"math/rand"
	"sync"
	"time"

	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"go.dedis.ch/cs438/utils"
)

// ReceivedAck contains the message and the packet received
type ReceivedAck struct {
	msg types.Message
	pkt transport.Packet
}

// AckTracker contains the information of the ack we should receive
type AckTracker struct {
	PacketID string
	Receiver string
	Msg      transport.Message
	Tic      time.Time
}

// ConcurrentMapChan

// ConcurrentMapChanAck is a threadsafe map
type ConcurrentMapChanAck struct {
	sync.Mutex
	opened map[string]bool
	items  map[string]chan ReceivedAck
}

// CreateIfNotExists declare a new entry if it doesn't exist yet
func (m *ConcurrentMapChanAck) CreateIfNotExists(key string) {
	m.Lock()
	if !m.opened[key] {
		m.items[key] = make(chan ReceivedAck)
		m.opened[key] = true
	}
	m.Unlock()
}

// Set is the threadsafe set function
func (m *ConcurrentMapChanAck) Set(key string, value chan ReceivedAck) {
	m.Lock()
	m.items[key] = value
	m.Unlock()
}

// Get is the threadsafe get function
func (m *ConcurrentMapChanAck) Get(key string) *chan ReceivedAck {
	m.Lock()
	item := m.items[key]
	m.Unlock()
	return &item
}

// Contains is the threadsafe contains function
func (m *ConcurrentMapChanAck) Contains(key string) bool {
	m.Lock()
	ok := m.opened[key]
	m.Unlock()
	return ok
}

type ConcurrentCatalog struct {
	sync.Mutex
	catalog peer.Catalog
}

func NewConcurrentCatalog() ConcurrentCatalog {
	return ConcurrentCatalog{catalog: make(peer.Catalog)}
}

func (m *ConcurrentCatalog) Get(key string) map[string]struct{} {
	m.Lock()
	defer m.Unlock()
	return m.catalog[key]
}

func (m *ConcurrentCatalog) GetOne(key string) string {
	allPeers := m.Get(key)
	if len(allPeers) == 0 {
		return ""
	}
	randomNb := rand.Intn(len(allPeers))
	k := 0
	for p := range allPeers {
		if randomNb == k {
			return p
		}
		k++
	}
	return ""
}

func (m *ConcurrentCatalog) Set(key string, value map[string]struct{}) {
	m.Lock()
	defer m.Unlock()
	m.catalog[key] = value
}

func (m *ConcurrentCatalog) Add(key string, value string) {
	m.Lock()
	defer m.Unlock()
	if _, ok := m.catalog[key]; !ok {
		m.catalog[key] = make(map[string]struct{})
	}
	m.catalog[key][value] = struct{}{}
}

func (m *ConcurrentCatalog) Copy() peer.Catalog {
	copiedCatalog := make(peer.Catalog)
	m.Lock()
	defer m.Unlock()
	for key, peerList := range m.catalog {
		copiedCatalog[key] = make(map[string]struct{})
		for p := range peerList {
			copiedCatalog[key][p] = struct{}{}
		}
	}
	return copiedCatalog
}

func (m *ConcurrentCatalog) ContainsHash(hash string) bool {
	_, ok := m.catalog[hash]
	return ok
}

func (m *ConcurrentCatalog) GetPeers() []string {
	return m.GetPeersExcepted([]string{})
}

func (m *ConcurrentCatalog) GetPeersExcepted(excepted []string) []string {
	// TODO: ugly complexity, update each time peer added in the catalog?
	peers := make([]string, 0)
	inIt := make(map[string]bool)
	m.Lock()
	for _, peerMap := range m.catalog {
		for p := range peerMap {
			if _, in := inIt[p]; !utils.Contains(excepted, p) && !in {
				inIt[p] = true
				peers = append(peers, p)
			}
		}
	}
	m.Unlock()
	return peers
}

func (m *ConcurrentCatalog) GetRandomPeer() string {
	return m.GetRandomPeerExcepted([]string{})
}
func (m *ConcurrentCatalog) GetRandomPeerExcepted(excepted []string) string {
	peers := m.GetPeersExcepted(excepted)
	// No peers
	if len(peers) == 0 {
		return ""
	}
	// Otherwise choose one
	chosenPeer := rand.Intn(len(peers))
	return peers[chosenPeer]
}

// Circuit

type NodeInfo struct {
	IP string
	Pk []byte
}

type NodesInfo struct {
	sync.Map
}

func (m *NodesInfo) Add(ip string, value NodeInfo) bool {
	_, loaded := m.LoadOrStore(ip, value)
	return !loaded
}

type RelayHttpRequest struct {
	uid             string
	destinationIp   string
	destinationPort string
	requestType     string
	data            []byte
}

// Proxy node refers to the first node trying to initiate the circuit
// Relay node is any node that receives messages and forwards it
// Exit node is the last node that sends the final request to an actual server
// Relay Circuit is used in nodes that are used as relay nodes
// Note that in the implementation a node can be both proxy and relay
type RelayCircuit struct {
	id            string        //Circuit ID: c1,c2,etc.
	firstNode     NodeInfo      //Refers to the initiating node for this circuit
	secondNode    NodeInfo      //Refers to the node on the other end of the circuit
	beforeCircuit *RelayCircuit //Refers to prev circuit in case of middle relay, ex. c1 if this is c2 and we're in non proxy node
	nextCircuit   *RelayCircuit // Refers to next circuit in case of non exit and non proxy node
}

// Refers to the circuit information retained by a proxy node which contains information about c1 which connects to first relay node
// Also includes extra information including which nodes are connected and their shared keys as well as metrics used for circuit selection
type ProxyCircuit struct {
	RelayCircuit
	associatedMessage   *RelayHttpRequest //In case we've actually started sending a message through this circuit
	created             time.Time
	lastUsed            time.Time
	lastMetricMessage   string          //Refers to message id of the last metric message
	lastMetricTimestamp time.Time       //Refers to the time the metric message was sent
	currentRtt          time.Duration   //Last Round trip recorded for this circuit
	rttMin              time.Duration   //Mininmum RTT recorded for this circuit
	ctt                 []time.Duration //last 5 Congestion time recordings; Ctt = Rtt - Rtt_Min
}

type Circuit struct {
	nodes     []string
	sharedKey map[string][]byte
}

func (c *Circuit) AmIProxy() bool {
	return len(c.nodes) > 2
}

func (c *Circuit) AmIExit() bool {
	return len(c.nodes) == 1
}

type Circuits struct {
	sync.Mutex
	circuits map[string]Circuit
}

func (c *Circuits) Get(uid string) Circuit {
	c.Lock()
	defer c.Unlock()
	return c.circuits[uid]
}

func (c *Circuits) GetAll() map[string]Circuit {
	c.Lock()
	defer c.Unlock()
	var cpy map[string]Circuit
	for uid, circuit := range c.circuits {
		cpy[uid] = circuit
	}
	return cpy
}

// GetProxyCircuits returns all the circuits that begins with this node
func (c *Circuits) GetProxyCircuits() map[string]Circuit {
	return c.Filter(func(circuit Circuit) bool { return circuit.AmIProxy() })
}

func (c *Circuits) Put(uid string, circuit Circuit) {
	c.Lock()
	defer c.Unlock()
	c.circuits[uid] = circuit
}

func (c *Circuits) Filter(filter func(c Circuit) bool) map[string]Circuit {
	var filtered map[string]Circuit
	for uid, circuit := range c.GetAll() {
		if filter(circuit) {
			filtered[uid] = circuit
		}
	}
	return filtered
}
