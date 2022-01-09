package impl

import (
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"go.dedis.ch/cs438/utils"
	"math/rand"
	"sync"
	"time"
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
