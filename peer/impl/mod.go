package impl

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"go.dedis.ch/cs438/crypto"
	"io/ioutil"
	"log"
	"math/rand"
	"sync"
	"time"

	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"go.dedis.ch/cs438/utils"
	"golang.org/x/xerrors"
)

// NewPeer creates a new peer. You can change the content and location of this
// function but you MUST NOT change its signature and package location.
func NewPeer(conf peer.Configuration) peer.Peer {
	n := node{
		// Disable log for passing all tests
		log:          log.New(ioutil.Discard, fmt.Sprintf("[%s] ", conf.Socket.GetAddress()), 0),
		conf:         conf,
		stop:         make(chan bool),
		isStopped:    false,
		wg:           sync.WaitGroup{},
		nRumors:      0,
		routingTable: make(peer.RoutingTable),
		viewTable:    make(peer.ViewTable),
		catalog:      NewConcurrentCatalog(),
		relayHandler: sync.Map{},

		ackReceived: ConcurrentMapChanAck{items: make(map[string]chan ReceivedAck), opened: make(map[string]bool)},
		ackHandler:  make(chan AckTracker),
		dataReply:   sync.Map{},
		searchReply: sync.Map{},
	}
	n.paxos = *n.NewPaxos(conf.PaxosID, conf.TotalPeers)
	var err error
	n.privateKey, err = crypto.GenerateKey(2048)
	n.log.Fatalf("Error generating rsa parameters : %v", err)

	// Register all callbacks for message types
	n.conf.MessageRegistry.RegisterMessageCallback(types.ChatMessage{}, n.execChatMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.RumorsMessage{}, n.execRumorMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.AckMessage{}, n.execAckMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.StatusMessage{}, n.execStatusMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.EmptyMessage{}, n.execEmptyMesssage) // Does nothing
	n.conf.MessageRegistry.RegisterMessageCallback(types.PrivateMessage{}, n.execPrivateMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.DataRequestMessage{}, n.execDataRequestMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.DataReplyMessage{}, n.execDataReplyMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.SearchRequestMessage{}, n.execSearchRequestMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.SearchReplyMessage{}, n.execSearchReplyMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.PaxosPrepareMessage{}, n.execPaxosPrepareMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.PaxosPromiseMessage{}, n.execPaxosPromiseMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.PaxosProposeMessage{}, n.execPaxosProposeMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.PaxosAcceptMessage{}, n.execPaxosAcceptMessage)
	n.conf.MessageRegistry.RegisterMessageCallback(types.TLCMessage{}, n.execTLCMessage)

	// Add own address in routing table
	n.AddPeer(n.conf.Socket.GetAddress())
	return &n
}

// node implements a peer to build a Peerster system
//
// - implements peer.Peer
type node struct {
	sync.RWMutex
	conf         peer.Configuration
	routingTable peer.RoutingTable
	viewTable    peer.ViewTable
	catalog      ConcurrentCatalog
	relayHandler sync.Map
	ackReceived  ConcurrentMapChanAck
	ackHandler   chan AckTracker
	dataReply    sync.Map
	searchReply  sync.Map
	nRumors      uint
	stop         chan bool
	wg           sync.WaitGroup
	isStopped    bool // TODO: turn this in something more beautiful (use wg value or stop channel)
	log          *log.Logger
	paxos        Paxos

	// Crypto parameters
	privateKey *rsa.PrivateKey
	keyExchangeChan ConcurrentMapChanMessage

	// Circuit
	directory NodesInfo
	circuits  Circuits

	proxyCircuits []*ProxyCircuit
	relayCircuits []*RelayCircuit

	proxiesLock sync.RWMutex
	relaysLock  sync.RWMutex

	circuitSelectionQuit chan struct{}
}

func (n *node) Addr() string {
	return n.conf.Socket.GetAddress()
}

// Start implements peer.Service
func (n *node) Start() error {
	// Add a waitgroup in order to keep track of the end of the Start function
	n.log.Println("Start main")

	err := n.StartIncomingMessages()
	if err != nil {
		return err
	}
	err = n.StartHeartBeat()
	if err != nil {
		return err
	}
	err = n.StartAntiEntropy()
	if err != nil {
		return err
	}
	// Launch the ack listener to handle ack receiving behavior
	err = n.StartAckListener()
	if err != nil {
		return err
	}

	return nil
}

func (n *node) StartIncomingMessages() error {
	// Launch a go routine that treats incoming packets and return if the Close function is called
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		for {
			select {
			// If stop on the channel received from Stop function, return
			case <-n.stop:
				n.log.Println("Stop received for Start")
				return
			// Else, handle the packet
			default:
				pkt, err := n.conf.Socket.Recv(1 * time.Second)
				if errors.Is(err, transport.TimeoutErr(0)) {
					continue
				}

				// Update the routing table
				if pkt.Msg.Type != types.DataRequestMessage.Name(types.DataRequestMessage{}) {
					// TODO: quid?
					n.SetRoutingEntry(pkt.Header.Source, pkt.Header.RelayedBy)
				}

				// If the packet is for the current node, process it
				if pkt.Header.Destination == n.conf.Socket.GetAddress() {
					n.log.Println(n.Addr(), " received a new message of type ", pkt.Msg.Type, " from ", pkt.Header.Source)
					err := n.conf.MessageRegistry.ProcessPacket(pkt)
					if err != nil {
						n.log.Printf("Error process packet %s: %v\n", n.conf.Socket.GetAddress(), err)
					}
					// Otherwise, send it to the next relay in order to reach the destination node
				} else {
					// Replace the address of the RelayedBy field with the current node address
					err := n.RelayPkt(pkt)
					if err != nil {
						n.log.Printf("Error relay packet %s:%v\n", n.conf.Socket.GetAddress(), err)
					}
				}
			}
		}
	}()
	return nil
}

func (n *node) StartHeartBeat() error {
	// Only start it if the interval is greater than 0
	if n.conf.HeartbeatInterval == 0 {
		return nil
	}

	n.log.Println("Launch goroutine for StartHeartBeat")
	// TODO: error not taken into account due to goroutine (n.log.)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		ticker := time.NewTicker(n.conf.HeartbeatInterval)
		for {
			select {
			// If stop on the channel received from Stop function, return
			case <-n.stop:
				ticker.Stop()
				n.log.Println("Stop received for StartHeartBeat")
				return
			// Else, send
			case <-ticker.C:
				heartbeat := types.EmptyMessage{}
				transportHeartbeat, err := n.conf.MessageRegistry.MarshalMessage(heartbeat)
				if err != nil {
					n.log.Printf("Error marshal message in heartbeat : %v\n", err)
				}
				err = n.Broadcast(transportHeartbeat)
				if err != nil {
					n.log.Printf("Error broadcast message in heartbeat : %v\n", err)
				}
			}
		}
	}()

	return nil
}

func (n *node) StartAntiEntropy() error {
	// Only start it if the interval is greater than 0
	if n.conf.AntiEntropyInterval <= 0 {
		return nil
	}

	n.log.Println("Launch goroutine for StartAntiEntropy")
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		ticker := time.NewTicker(n.conf.AntiEntropyInterval)
		for {
			select {
			// If stop on the channel received from Stop function, return
			case <-n.stop:
				ticker.Stop()
				n.log.Println("Stop received for StartAntiEntropy")
				return
			// Else, send
			case <-ticker.C:
				randomNeighbor := n.PickRandomNeighbor()
				if randomNeighbor != "" {
					err := n.SendStatusMessage(randomNeighbor)
					if err != nil {
						n.log.Printf("Error anti entropy sending status message to %s : %v\n", randomNeighbor, err)
					}
					n.log.Printf("Sent a status message to %s\n", randomNeighbor)
				}

			}
		}
	}()

	return nil
}

func (n *node) StartAckListener() error {
	if n.conf.AckTimeout <= 0 {
		return nil
	}

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		n.log.Println("Launch goroutine for StartAckListener")
		for {
			select {
			// If stop on the channel received from Stop function, return
			case <-n.stop:
				n.log.Println("Stop received for StartAckListener")
				return
			case tracker := <-n.ackHandler:
				// Listen to a particular tracker
				n.log.Println("Track a new ack : ", tracker.PacketID)
				n.log.Println("Value of chan ", n.ackReceived.Get(tracker.PacketID))
				n.ackReceived.CreateIfNotExists(tracker.PacketID)
				err := n.ListenParticularAck(tracker)
				if err != nil {
					n.log.Printf("Ack listen to particular ack: %v\n", err)
				}
			}
		}
	}()

	return nil
}

func (n *node) ListenParticularAck(tracker AckTracker) error {

	n.wg.Add(1)
	go func() {
		defer n.wg.Done()

		overhead := time.Since(tracker.Tic)
		waitingTime := n.conf.AckTimeout - overhead

		select {
		// If stop on the channel received from Stop function, return
		case <-n.stop:
			n.log.Println("Stop received for ListenParticularAck")
			return

		// Processed the message if ack received
		case <-*n.ackReceived.Get(tracker.PacketID):
			n.log.Println("Received ack on receivedAck chan for packet ", tracker.PacketID)
			return
		case <-time.After(waitingTime):
			n.log.Println("Did not received ack on receivedAck for packet ", tracker.PacketID)
			// If timeout, send the rumor message to another peer
			nextPeer := n.PickRandomNeighborsExcepted([]string{tracker.Receiver})
			if nextPeer != "" {
				err := n.SendRumor(n.conf.Socket.GetAddress(), nextPeer, tracker.Msg)
				if err != nil {
					n.log.Printf("Error while sending rumors to another random neighbor, %v\n", err)
				}
			}
			return

		}

	}()
	return nil
}

// Stop implements peer.Service
func (n *node) Stop() error {
	// If the node is already closed, throw an error
	if n.isStopped {
		return xerrors.Errorf("Node (%s) already closed\n", n.conf.Socket.GetAddress())
	}

	// Send a signal on the stop channel in order to notify all goroutines to finish
	close(n.stop)

	// Wait for the goroutines to stop
	n.wg.Wait()

	// Then set the isStopped bool to true to keep track of the status of the node
	n.isStopped = true
	return nil
}

// AddPeer implements peer.Service
func (n *node) AddPeer(addr ...string) {
	// Lock the whole routing table and set all neighbors before AddPeer or SetRoutingEntry can be called from another thread
	n.Lock()
	defer n.Unlock()
	for _, neighbor := range addr {
		n.routingTable[neighbor] = neighbor
	}
}

// GetRoutingTable implements peer.Service
func (n *node) GetRoutingTable() peer.RoutingTable {
	n.Lock()
	defer n.Unlock()
	// TODO : find a nicer way to copy map
	copyTable := make(peer.RoutingTable, len(n.routingTable))
	for key, value := range n.routingTable {
		copyTable[key] = value
	}
	return copyTable
}

// SetRoutingEntry implements peer.Service
func (n *node) SetRoutingEntry(origin, relayAddr string) {
	n.Lock()
	defer n.Unlock()

	// Remove the origin address from the routing table if no relay address
	if relayAddr == "" && relayAddr != n.conf.Socket.GetAddress() { // TODO: Possible to remove itself from the routing table?
		delete(n.routingTable, origin)
	} else { // Otherwise, update the relay address
		n.routingTable[origin] = relayAddr
	}
}

func (n *node) GetStatusMessage() types.StatusMessage {
	statusMsg := types.StatusMessage{}

	// TODO: build a thread safe map instead of locking the whole node
	n.Lock()
	defer n.Unlock()
	for p, rumors := range n.viewTable {
		statusMsg[p] = uint(len(rumors))
	}
	return statusMsg
}

func (n *node) GetNeighborsExcepted(excluded []string) []string {
	n.Lock()
	defer n.Unlock()
	var neighbors []string
	for neighbor := range n.routingTable {
		if neighbor == n.conf.Socket.GetAddress() || utils.Contains(excluded, neighbor) {
			continue
		}
		neighbors = append(neighbors, neighbor)
	}
	return neighbors
}

func (n *node) GetNeighbors() []string {
	return n.GetNeighborsExcepted([]string{})
}

func (n *node) PickRandomNeighborsExcepted(excluded []string) string {
	neighbors := n.GetNeighborsExcepted(excluded)
	if len(neighbors) == 0 {
		return ""
	}
	chosenNeighbor := rand.Intn(len(neighbors))
	return neighbors[chosenNeighbor]
}

func (n *node) PickRandomNeighbor() string {
	return n.PickRandomNeighborsExcepted([]string{})
}

func (n *node) PackRumors(messages []transport.Message) (transport.Message, []types.Rumor, error) {
	var rumors []types.Rumor
	for _, msg := range messages {
		n.Lock()
		n.nRumors++
		rumor := types.Rumor{Origin: n.conf.Socket.GetAddress(), Sequence: n.nRumors, Msg: &msg}
		n.viewTable[n.Addr()] = append(n.viewTable[n.Addr()], rumor)
		n.log.Printf("Added rumor %d to viewtable\n", n.nRumors)
		rumors = append(rumors, rumor)
		n.Unlock()
	}
	rumorsMsg := types.RumorsMessage{Rumors: rumors}
	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(rumorsMsg)
	return transportMsg, rumors, err
}

func (n *node) RelayPkt(pkt transport.Packet) error {
	n.log.Printf("Peer %s relayed packet from %s and %s\n", n.Addr(), pkt.Header.Source, pkt.Header.Destination)
	pkt.Header.RelayedBy = n.Addr()

	return n.conf.Socket.Send(pkt.Header.Destination, pkt, 0)
}

// UnicastComplete implements peer.Messaging
func (n *node) UnicastComplete(source string, dest string, msg transport.Message) (transport.Packet, error) {
	relayedBy := n.conf.Socket.GetAddress()

	// Get relay from routingTable and check if a route exists, otherwise return an error
	n.Lock()
	relay := n.routingTable[dest]
	n.Unlock()
	if relay == "" {
		n.log.Printf("Node %s does not have a route to %s", source, dest)
		return transport.Packet{}, xerrors.Errorf("Node %s does not have a route to %s", source, dest)
	}

	// Create the packet
	header := transport.NewHeader(source, relayedBy, dest, 0)
	pkt := transport.Packet{
		Header: &header,
		Msg:    &msg,
	}

	// Then send the packet to the next relay node
	err := n.conf.Socket.Send(relay, pkt, 0)
	if err != nil {
		return transport.Packet{}, err
	}

	return pkt, nil

}

func (n *node) Unicast(dest string, msg transport.Message) error {
	_, err := n.UnicastComplete(n.conf.Socket.GetAddress(), dest, msg)
	return err
}

func (n *node) UnicastDirect(source string, dest string, msg transport.Message) error {
	relayedBy := n.conf.Socket.GetAddress()

	// Create the packet
	header := transport.NewHeader(source, relayedBy, dest, 0)
	pkt := transport.Packet{
		Header: &header,
		Msg:    &msg,
	}

	// Then send the packet to the next relay node
	err := n.conf.Socket.Send(dest, pkt, 1*time.Second)
	if err != nil {
		return err
	}
	return nil
}

func (n *node) Broadcast(msg transport.Message) error {
	transportMsg, _, err := n.PackRumors([]transport.Message{msg})
	if err != nil {
		return err
	}

	// Send the rumor to a random neighbor
	randomNeighbor := n.PickRandomNeighbor()
	n.log.Println("Send broadcast to neighbor ", randomNeighbor)
	if randomNeighbor != "" {
		err = n.SendRumor(n.conf.Socket.GetAddress(), randomNeighbor, transportMsg)
		if err != nil {
			return err
		}

	}

	// Process the message locally
	n.log.Println("Process in local a rumor of type ", msg.Type)
	header := transport.NewHeader(n.Addr(), n.Addr(), n.Addr(), 0)
	err = n.conf.MessageRegistry.ProcessPacket(transport.Packet{Header: &header, Msg: &msg})
	if err != nil {
		return err
	}

	return nil
}
