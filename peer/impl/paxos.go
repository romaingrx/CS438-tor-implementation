package impl

import (
	"encoding/hex"
	"github.com/rs/xid"
	"go.dedis.ch/cs438/storage"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"go.dedis.ch/cs438/utils"
	"strconv"
	"sync"
	"time"
)

type Paxos struct {
	sync.Mutex
	id, maxID, worldSize, step uint
	latestAcceptedValue        LatestAcceptedValueStruct

	// Callbacks channels
	promiseCallbacks, acceptCallbacks, tlcCallbacks chan types.Message
	notifyPaxosProcess                              chan bool
}
type LatestAcceptedValueStruct struct {
	ID    uint
	Value types.PaxosValue
}

func (l *LatestAcceptedValueStruct) IsEmpty() bool {
	return l.ID == 0 && l.Value.Filename == "" && l.Value.Metahash == "" && l.Value.UniqID == ""
}

func (n *node) NewPaxos(id, worldSize uint) *Paxos {
	p := Paxos{
		id:        id,
		worldSize: worldSize,

		promiseCallbacks:   make(chan types.Message),
		acceptCallbacks:    make(chan types.Message), // TODO hw3: Map[string] chan types.Message : mapped to each UniqueID?
		tlcCallbacks:       make(chan types.Message),
		notifyPaxosProcess: make(chan bool),
	}

	go n.StartListeningTLCAndAccept(p.tlcCallbacks, p.acceptCallbacks, p.notifyPaxosProcess)

	return &p
}

func (p *Paxos) GetStep() uint {
	p.Lock()
	defer p.Unlock()
	return p.step
}

func (p *Paxos) GetMaxID() uint {
	p.Lock()
	defer p.Unlock()
	return p.maxID
}

func (p *Paxos) GetID() uint {
	p.Lock()
	defer p.Unlock()
	return p.id
}

func (p *Paxos) GetPrevID() uint {
	p.Lock()
	defer p.Unlock()
	return p.id - p.worldSize
}

func (p *Paxos) GetAndIncrementID() uint {
	p.Lock()
	defer p.Unlock()
	defer func() { p.id = p.id + p.worldSize }()
	return p.id
}

func (p *Paxos) GetLatestAcceptedValue() LatestAcceptedValueStruct {
	p.Lock()
	defer p.Unlock()
	return p.latestAcceptedValue
}

func (p *Paxos) IncrStep(Incremental uint) {
	p.Lock()
	defer p.Unlock()
	p.step += Incremental
}

func (n *node) ReachedThreshold(Value int) bool {
	return n.conf.PaxosThreshold(n.paxos.worldSize) <= Value
}

func (n *node) RegisterAcceptedValue(ID uint, AcceptedValue types.PaxosValue) {
	n.paxos.Lock()
	defer n.paxos.Unlock()
	// Register the accepted value as the latest one
	n.paxos.latestAcceptedValue = LatestAcceptedValueStruct{ID: ID, Value: AcceptedValue}
}

func (p *Paxos) RegisterProposalID(ProposalID uint) {
	p.Lock()
	defer p.Unlock()
	p.maxID = ProposalID
}

func (n *node) CreateBlock(Value types.PaxosValue) types.BlockchainBlock {
	block := types.BlockchainBlock{
		Index:    n.paxos.GetStep(),
		Hash:     n.GetHash(Value),
		Value:    Value,
		PrevHash: n.GetPrevHash(),
	}
	return block
}

func (n *node) GetHash(Value types.PaxosValue) []byte {
	concatenateString := strconv.Itoa(int(n.paxos.GetStep())) + Value.UniqID + Value.Filename + Value.Metahash + string(n.GetPrevHash())
	_, hash := utils.Sha256Encode([]byte(concatenateString))
	return hash
}

func (n *node) GetPrevHash() []byte {
	prevHash := n.conf.Storage.GetBlockchainStore().Get(storage.LastBlockKey)
	if prevHash == nil {
		return []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	}
	return prevHash
}

func (n *node) StartListeningTLCAndAccept(tlcCallbacks, acceptCallbacks chan types.Message, notifyPaxosProcess chan bool) {
	var storedTLCMessages = make(map[uint][]types.TLCMessage)
	var storedAcceptMessages = make(map[uint][]types.PaxosAcceptMessage)
	var broadcastedTLC = make(map[string]bool)

	tlcConsensusReached := func(TLCMsg types.TLCMessage) error {
		n.log.Println("TLC consensus reached for step ", n.paxos.GetStep())
		blockChainStore := n.conf.Storage.GetBlockchainStore()

		// 1. Add the block to its own blockchain
		block := TLCMsg.Block
		hashString := hex.EncodeToString(block.Hash)
		blockMarshalled, err := block.Marshal()
		if err != nil {
			return err
		}
		blockChainStore.Set(hashString, blockMarshalled)      // Set the new block
		blockChainStore.Set(storage.LastBlockKey, block.Hash) // Set the previous hash

		// 2. Set the name/metahash association in the name store
		n.conf.Storage.GetNamingStore().Set(block.Value.Filename, []byte(block.Value.Metahash))

		// 3. In case the peer hasn’t broadcasted a TLCMessage before: broadcast the TLCMessage
		if !broadcastedTLC[hashString] {
			n.log.Println("Broadcast a TLC message ", TLCMsg)
			broadcastedTLC[hashString] = true
			err := n.BroadcastTLC(TLCMsg)
			if err != nil {
				n.log.Println(err)
			}
		}

		// 4. Increase by 1 its internal TLC step
		n.paxos.IncrStep(uint(1))

		return nil
	}

	var checkCatchup func()
	checkCatchup = func() {
		if n.ReachedThreshold(len(storedTLCMessages[n.paxos.GetStep()])) {
			n.log.Println("Consensus reached at the TLC layer, send tlc for step ", n.paxos.GetStep())
			msg := storedTLCMessages[n.paxos.GetStep()][0]
			err := tlcConsensusReached(msg)
			if err != nil {
				n.log.Println(err)
			}
		} else if n.ReachedThreshold(len(storedAcceptMessages[n.paxos.GetStep()])) {
			n.log.Println(n.conf.Socket.GetAddress(), " :: Consensus reached at the paxos layer, send tlc for step ", n.paxos.GetStep())

			acceptMsg := storedAcceptMessages[n.paxos.GetStep()][0]
			var tlcMsg types.TLCMessage
			if acceptMsg.ID != n.paxos.GetPrevID() { // Acceptor
				if len(storedTLCMessages[n.paxos.GetStep()]) == 0 {
					// If we don't have received a TLC message from the proposer, wait for it before reaching the consensus
					return
				}
				// Otherwise, get it from the proposer and process it
				tlcMsg = storedTLCMessages[n.paxos.GetStep()][0]
			} else { // Proposer
				// Notify the Paxos process that we have reached a consensus, so it does not need to wait more
				notifyPaxosProcess <- true
				block := n.CreateBlock(acceptMsg.Value)
				tlcMsg = types.TLCMessage{
					Step:  n.paxos.GetStep(),
					Block: block,
				}
			}
			err := tlcConsensusReached(tlcMsg)
			if err != nil {
				n.log.Println(err)
			}
		} else {
			return
		}
		checkCatchup()
	}

	addTLCClock := func(msg types.Message) {
		if tlcMsg, okTLC := msg.(types.TLCMessage); okTLC {
			storedTLCMessages[tlcMsg.Step] = append(storedTLCMessages[tlcMsg.Step], tlcMsg)
		} else if acceptMsg, okAccept := msg.(types.PaxosAcceptMessage); okAccept {
			storedAcceptMessages[acceptMsg.Step] = append(storedAcceptMessages[acceptMsg.Step], acceptMsg)
		} else {
			n.log.Printf("wrong type: %T", msg)
			return
		}
		checkCatchup()
	}

	var raw types.Message
	for {
		select {
		case raw = <-tlcCallbacks:
			addTLCClock(raw)
		case raw = <-acceptCallbacks:
			addTLCClock(raw)
		}
	}
}

func (n *node) BeginPaxosConsensus(name, mh string) {
	step := n.paxos.GetStep()
	proposalID := n.paxos.GetAndIncrementID()

	// Broadcast a prepare message to all peers
	err := n.SendPrepareMessage(step, proposalID)
	if err != nil {
		n.log.Println(err)
	}

	// Gather all promises message
	reachedThreshold := n.WaitAllPromises(proposalID)
	if !reachedThreshold {
		// If the threshold has not been reached, begin a new paxos consensus on the same values
		n.BeginPaxosConsensus(name, mh)
		return
	}

	// If the threshold has been reached, broadcast a propose message to all perrs
	paxosValue := types.PaxosValue{
		Filename: name,
		Metahash: mh,
		UniqID:   xid.New().String(),
	}
	err = n.SendProposeMessage(step, proposalID, paxosValue)
	if err != nil {
		n.log.Println(err)
		return // TODO hw3 : return?
	}

	// Gather all accept message
	select {
	case <-n.paxos.notifyPaxosProcess:
		return
	case <-time.After(n.conf.PaxosProposerRetry):
		n.BeginPaxosConsensus(name, mh)
	}

}

func (n *node) NotifyReceivedPromise(msg types.PaxosPromiseMessage, pkt transport.Packet) error {
	go func() {
		n.paxos.promiseCallbacks <- msg
	}()
	return nil
}

func (n *node) NotifyReceivedAccept(msg types.PaxosAcceptMessage, pkt transport.Packet) error {
	go func() {
		n.paxos.acceptCallbacks <- msg
	}()
	return nil
}

func (n *node) NotifyReceivedTLC(msg types.TLCMessage, pkt transport.Packet) error {
	go func() {
		n.paxos.tlcCallbacks <- msg
	}()
	return nil
}

func (n *node) WaitAllPromises(ID uint) bool {
	var stopListening = make(chan bool)
	defer func() { close(stopListening) }()

	enoughAnswers := make(chan bool)
	nCountUniqueID := make(map[uint]int)
	countAnswers := func() {
		for {
			// If we've reached the threshold
			if n.ReachedThreshold(nCountUniqueID[ID]) {
				// TODO hw3: return or still collect arriving answers (waiting goroutines)?
				enoughAnswers <- true
				return
			}
			select {
			case msg := <-n.paxos.promiseCallbacks:
				if promiseMsg, ok := msg.(types.PaxosPromiseMessage); ok {
					nCountUniqueID[promiseMsg.ID]++
				} else {
					n.log.Printf("Promise message not good type : %T\n", msg)
				}
			case <-stopListening:
				return
			}
		}
	}

	// Count the received answers on a goroutine
	go countAnswers()

	select {
	// If we've reached the threshold, return true
	case <-enoughAnswers:
		return true
		// Otherwise, return false and resend a prepare message
	case <-time.After(n.conf.PaxosProposerRetry):
		return false
	}
}

func (n *node) SendPrepareMessage(step, id uint) error {
	prepareMsg := types.PaxosPrepareMessage{
		Step:   step,
		ID:     id,
		Source: n.conf.Socket.GetAddress(),
	}

	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(prepareMsg)
	if err != nil {
		return err
	}

	err = n.Broadcast(transportMsg)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) SendPromiseMessage(prepareMsg types.PaxosPrepareMessage) error {
	promiseMsg := types.PaxosPromiseMessage{
		Step:          prepareMsg.Step,
		ID:            prepareMsg.ID, // TODO hw3: not sure if maxID or id
		AcceptedID:    0,
		AcceptedValue: nil,
	}

	// Fill the promise message with the latest accepted value if exists
	latestAcceptedValue := n.paxos.GetLatestAcceptedValue()
	if !latestAcceptedValue.IsEmpty() {
		promiseMsg.AcceptedID = latestAcceptedValue.ID
		promiseMsg.AcceptedValue = &latestAcceptedValue.Value
	}

	transportPromiseMsg, err := n.conf.MessageRegistry.MarshalMessage(promiseMsg)
	if err != nil {
		return err
	}

	privateMsg := types.PrivateMessage{Recipients: map[string]struct{}{prepareMsg.Source: {}}, Msg: &transportPromiseMsg}

	transportPrivateMsg, err := n.conf.MessageRegistry.MarshalMessage(privateMsg)
	if err != nil {
		return err
	}

	return n.Broadcast(transportPrivateMsg)
}

func (n *node) SendProposeMessage(step, id uint, PaxosValue types.PaxosValue) error {
	proposeMsg := types.PaxosProposeMessage{
		Step:  step,
		ID:    id,
		Value: PaxosValue,
	}

	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(proposeMsg)
	if err != nil {
		return err
	}

	return n.Broadcast(transportMsg)
}

func (n *node) SendAcceptMessage(proposeMsg types.PaxosProposeMessage) error {
	acceptMsg := types.PaxosAcceptMessage(proposeMsg)

	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(acceptMsg)
	if err != nil {
		return err
	}

	return n.Broadcast(transportMsg)
}

func (n *node) BroadcastTLC(TLCMsg types.TLCMessage) error {
	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(TLCMsg)
	if err != nil {
		return err
	}

	n.log.Println("Broadcast TLC message for step ", TLCMsg.Step)

	return n.Broadcast(transportMsg)
}
