package impl

import (
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
	"math/rand"
	"regexp"
	"sort"
	"time"
)

func (n *node) execChatMessage(msg types.Message, pkt transport.Packet) error {
	_, ok := msg.(*types.ChatMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}
	n.log.Println("Received a chat message ", msg.String())

	return nil
}

func (n *node) execRumorMessage(msg types.Message, pkt transport.Packet) error {
	rumorsMsg, ok := msg.(*types.RumorsMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}
	n.log.Println("Received a rumor message ", rumorsMsg.String())

	newRumor := false
	for _, r := range rumorsMsg.Rumors {
		n.Lock()
		viewOrigin := n.viewTable[r.Origin]
		n.Unlock()
		expected := int(r.Sequence) == len(viewOrigin)+1
		newRumor = newRumor || expected
		n.log.Printf("Expected rumor %d received from %s : %d\n", r.Sequence, r.Origin, expected)
		if expected {
			// Update the routing table
			n.SetRoutingEntry(r.Origin, pkt.Header.RelayedBy)

			// Keep track of the rumor
			n.Lock()
			n.viewTable[r.Origin] = append(viewOrigin, r)
			n.Unlock()

			// Build new packet based on the rumor and process it internally
			newPkt := transport.Packet{
				Header: pkt.Header,
				Msg:    r.Msg,
			}
			err := n.conf.MessageRegistry.ProcessPacket(newPkt)
			if err != nil {
				n.log.Printf("Process packet not possible in exec rumor : %v\n", err)
			}

		}
	}

	// Send ack to the sender
	err := n.SendAck(pkt)
	if err != nil {
		n.log.Printf("Impossible to send Ack : %v\n", err)
	}

	if newRumor {
		// Send rumors to a random neighbor excepted the source of the packet
		randomNeighbor := n.PickRandomNeighborsExcepted([]string{pkt.Header.Source, pkt.Header.RelayedBy})
		if randomNeighbor != "" {
			n.log.Printf("Received new rumors so send the rumors to random neighbor : %s\n", randomNeighbor)
			transportMsg, err := n.conf.MessageRegistry.MarshalMessage(msg)
			if err != nil {
				return err
			}
			return n.SendRumor(pkt.Header.Source, randomNeighbor, transportMsg)
		}
	}

	return nil
}

func (n *node) execAckMessage(msg types.Message, pkt transport.Packet) error {
	ackMsg, ok := msg.(*types.AckMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	if !n.ackReceived.Contains(ackMsg.AckedPacketID) {
		n.log.Println("Ack not waited ", ackMsg.AckedPacketID)
	}

	// Notify the channel that we have received the ack
	go func() {
		*n.ackReceived.Get(ackMsg.AckedPacketID) <- ReceivedAck{msg: msg, pkt: pkt}
	}()

	// Process the status message
	statusTransport, err := n.conf.MessageRegistry.MarshalMessage(ackMsg.Status)
	if err != nil {
		n.log.Printf("Error while trying to process ack message : %v\n", err)
		return err
	}
	statusPkt := transport.Packet{Header: pkt.Header, Msg: &statusTransport}
	err = n.conf.MessageRegistry.ProcessPacket(statusPkt)
	if err != nil {
		n.log.Printf("Error while trying to process ack message : %v\n", err)
		return err
	}
	n.log.Printf("Processed ack message from %s\n", pkt.Header.Source)

	return nil
}

func (n *node) CompareStatus(remoteStatus types.StatusMessage) (bool, bool, []types.Rumor) {
	selfStatus := n.GetStatusMessage()

	selfMissing := false
	remoteMissing := false
	var remoteMissingRumors []types.Rumor

	// TODO : use a particular lock for the viewTable
	for key, remoteValue := range remoteStatus {
		if selfValue, ok := selfStatus[key]; ok {
			if selfValue > remoteValue {
				remoteMissing = true
				// Taken into account that we begin the rumors sequence at 1

				n.Lock()
				missingValues := n.viewTable[key][remoteValue:]
				n.Unlock()

				remoteMissingRumors = append(remoteMissingRumors, missingValues...)
			} else if selfValue < remoteValue {
				selfMissing = true
			}
		} else {
			selfMissing = true
		}
	}

	// Check if remote peer miss some neighbors that we have
	for key := range selfStatus {
		if _, ok := remoteStatus[key]; !ok {
			remoteMissing = true

			n.Lock()
			missingValues := n.viewTable[key]
			n.Unlock()

			remoteMissingRumors = append(remoteMissingRumors, missingValues...)
		}
	}

	sort.Slice(remoteMissingRumors, func(k, l int) bool {
		return remoteMissingRumors[k].Sequence < remoteMissingRumors[l].Sequence
	})

	return selfMissing, remoteMissing, remoteMissingRumors
}

func (n *node) execStatusMessage(msg types.Message, pkt transport.Packet) error {
	remoteStatus, ok := msg.(*types.StatusMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// Four possible cases:
	// 1. The remote peer has Rumors that the peer P doesn't have.
	// 2. The peer P has Rumors that the remote peer doesn't have.
	// 3. Both peers have new messages.
	// 4. Both peers have the same view.
	selfMissing, remoteMissing, remoteMissingRumors := n.CompareStatus(*remoteStatus)

	// If we miss some rumors, send back our statusMessage to the sender to get the update
	if selfMissing {
		err := n.SendStatusMessage(pkt.Header.Source)
		if err != nil {
			return err
		}
	}
	// If the remote peer miss some rumors, we send them to it
	if remoteMissing {
		// Transform the message to a transport message
		transportRumors, err := n.conf.MessageRegistry.MarshalMessage(types.RumorsMessage{Rumors: remoteMissingRumors})
		if err != nil {
			return nil
		}

		// Then send it to the remote peer
		err = n.Unicast(pkt.Header.Source, transportRumors)
		if err == nil {
			return nil
		}
	}
	// If both are up-to-date, with a certain probability, send a status message to a random neighbor
	if !selfMissing && !remoteMissing {
		if rand.Float64() <= n.conf.ContinueMongering {
			randomNeighbor := n.PickRandomNeighborsExcepted([]string{pkt.Header.Source, pkt.Header.RelayedBy})
			if randomNeighbor == "" {
				return xerrors.Errorf("No random neighbour to continue mongering")
			}
			err := n.SendStatusMessage(randomNeighbor)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (n *node) execEmptyMesssage(msg types.Message, pkt transport.Packet) error {
	_, ok := msg.(*types.EmptyMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}
	n.log.Printf("Received an empty packet from %s\n ", pkt.Header.Source)

	return nil
}

func (n *node) execPrivateMessage(msg types.Message, pkt transport.Packet) error {
	privateMsg, ok := msg.(*types.PrivateMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}
	n.log.Println("Exec private message ", pkt.Header.PacketID)
	for key := range privateMsg.Recipients {
		// If we are in the recipients, process the message it contains
		if key == n.Addr() {
			processedPkt := transport.Packet{
				Header: pkt.Header,
				Msg:    privateMsg.Msg,
			}
			err := n.conf.MessageRegistry.ProcessPacket(processedPkt)
			if err != nil {
				return err
			}

			return nil
		}
	}

	return nil
}

func (n *node) execDataRequestMessage(msg types.Message, pkt transport.Packet) error {
	dataRequestMessage, ok := msg.(*types.DataRequestMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	bytes := n.conf.Storage.GetDataBlobStore().Get(dataRequestMessage.Key)

	err := n.SendDataReplyMessage(bytes, *dataRequestMessage, pkt.Header.Source)
	if err != nil {
		n.log.Println(err)
	}

	return nil
}

func (n *node) execDataReplyMessage(msg types.Message, pkt transport.Packet) error {
	dataReplyMsg, ok := msg.(*types.DataReplyMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	go func() {
		channel, ok := n.dataReply.Load(dataReplyMsg.RequestID)
		if !ok {
			n.log.Printf("Channel was not created for the request %s\n", dataReplyMsg.RequestID)
			return
		}

		channel.(chan types.DataReplyMessage) <- *dataReplyMsg // TODO: does it work?
		n.log.Printf("dataReplyMsg sent on the channel for requestID %s\n", dataReplyMsg.RequestID)
	}()

	return nil
}

func (n *node) execSearchRequestMessage(msg types.Message, pkt transport.Packet) error {
	searchRequestMsg, ok := msg.(*types.SearchRequestMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// TODO : add relay handle
	_, loaded := n.relayHandler.LoadOrStore(searchRequestMsg.RequestID, searchRequestMsg.Origin)
	n.log.Printf("Set the relay %s for requestID %s\n", searchRequestMsg.Origin, searchRequestMsg.RequestID)
	if loaded {
		return nil
	}

	reg, err := regexp.Compile(searchRequestMsg.Pattern)
	if err != nil {
		return err
	}

	if searchRequestMsg.Budget > 1 {
		// TODO URGENT : How to choose subpeer timeout?
		searchRequestRelayed := types.SearchRequestMessage{
			RequestID: searchRequestMsg.RequestID,
			Origin:    n.conf.Socket.GetAddress(),
			Budget:    searchRequestMsg.Budget - 1,
			Pattern:   searchRequestMsg.Pattern,
		}
		_, err = n.searchAllPeer(400*time.Millisecond, searchRequestRelayed, []string{n.conf.Socket.GetAddress(), pkt.Header.Source, pkt.Header.RelayedBy})
		if err != nil {
			n.log.Printf("%v\n", err)
		}
	}
	names, err := n.searchAllLocal(*reg, true)
	if err != nil {
		n.log.Printf("%v\n", err)
		return err
	}

	err = n.SendSearchReplyMessage(names, *searchRequestMsg)
	if err != nil {
		n.log.Println(err)
	}

	return nil
}

func (n *node) execSearchReplyMessage(msg types.Message, pkt transport.Packet) error {
	searchReplyMsg, ok := msg.(*types.SearchReplyMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	relayTarget, ok := n.relayHandler.Load(searchReplyMsg.RequestID)
	if ok {
		relayTargetString := relayTarget.(string)
		n.log.Println("Send the answer to the relay ", relayTargetString)
		header := transport.NewHeader(pkt.Header.Source, n.conf.Socket.GetAddress(), relayTargetString, 0)

		relayPkt := transport.Packet{Header: &header, Msg: pkt.Msg}

		err := n.conf.Socket.Send(relayTargetString, relayPkt, 0)
		if err != nil {
			n.log.Println(err)
		}

	}

	go func() {
		channel, ok := n.searchReply.Load(searchReplyMsg.RequestID)
		if !ok {
			n.log.Printf("Channel was not created for the search request %s\n", searchReplyMsg.RequestID)
			return
		}

		channel.(chan types.SearchReplyMessage) <- *searchReplyMsg
		n.log.Printf("searchReplyMsg sent on the channel for requestID %s\n", searchReplyMsg.RequestID)
	}()

	for _, fileInfo := range searchReplyMsg.Responses {
		if fileInfo.Chunks != nil {
			// fmt.Printf("TREAT NAME %s WITH METAHASH %s FOR PEER %s\n", fileInfo.Name, string(fileInfo.Metahash), pkt.Header.Source)
			err := n.Tag(fileInfo.Name, fileInfo.Metahash)
			if err != nil {
				n.log.Printf("%v\n", err)
				continue
			}
			n.UpdateCatalog(fileInfo.Metahash, pkt.Header.Source)
			for _, chunk := range fileInfo.Chunks {
				if len(chunk) > 0 {
					n.log.Println("Update the catalog for ", string(chunk), " with address ", pkt.Header.Source)
					n.UpdateCatalog(string(chunk), pkt.Header.Source)
				}
			}
		}
	}

	return nil
}

func (n *node) execPaxosPrepareMessage(msg types.Message, pkt transport.Packet) error {
	paxosPrepareMsg, ok := msg.(*types.PaxosPrepareMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// 1. Ignore messages whose Step field do not match the current logical clock
	if paxosPrepareMsg.Step != n.paxos.GetStep() {
		return xerrors.Errorf("Step %u is not the same as our current step %u", paxosPrepareMsg.Step, n.paxos.GetStep())
	}
	// 2. Ignore messages whose id is not greater than maxID
	if !(paxosPrepareMsg.ID > n.paxos.GetMaxID()) {
		return xerrors.Errorf("The id %u is not greater than the current maxID %u", paxosPrepareMsg.ID, n.paxos.GetMaxID())
	}

	// Store the current proposed ID
	n.paxos.RegisterProposalID(paxosPrepareMsg.ID)

	// 3. Respond with a PaxosPromiseMessage matching the PaxosPrepareMessage
	return n.SendPromiseMessage(*paxosPrepareMsg)
}

func (n *node) execPaxosPromiseMessage(msg types.Message, pkt transport.Packet) error {
	paxosPromiseMsg, ok := msg.(*types.PaxosPromiseMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// 1. Ignore messages whose Step field do not match the current logical clock
	if paxosPromiseMsg.Step != n.paxos.GetStep() {
		return xerrors.Errorf("Step %u is not the same as our current step %u", paxosPromiseMsg.Step, n.paxos.GetStep())
	}
	// 2. Ignore messages whose id is not greater than maxID
	if paxosPromiseMsg.ID != n.paxos.GetMaxID() {
		return xerrors.Errorf("The id %u is not greater than the current maxID %u", paxosPromiseMsg.ID, n.paxos.GetMaxID())
	}

	return n.NotifyReceivedPromise(*paxosPromiseMsg, pkt)
}

func (n *node) execPaxosProposeMessage(msg types.Message, pkt transport.Packet) error {
	paxosProposeMsg, ok := msg.(*types.PaxosProposeMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// 1. Ignore messages whose Step field do not match the current logical clock
	if paxosProposeMsg.Step != n.paxos.GetStep() {
		return xerrors.Errorf("Step %u is not the same as our current step %u", paxosProposeMsg.Step, n.paxos.GetStep())
	}
	// 2. Ignore messages whose id is not greater than maxID
	if paxosProposeMsg.ID != n.paxos.GetMaxID() {
		return xerrors.Errorf("The id %u is not greater than the current maxID %u", paxosProposeMsg.ID, n.paxos.GetMaxID())
	}

	// Register the proposed value
	n.RegisterAcceptedValue(paxosProposeMsg.ID, paxosProposeMsg.Value)

	// 3. Respond with a PaxosAcceptMessage matching the PaxosProposeMessage
	return n.SendAcceptMessage(*paxosProposeMsg)
}

func (n *node) execPaxosAcceptMessage(msg types.Message, pkt transport.Packet) error {
	paxosAcceptMsg, ok := msg.(*types.PaxosAcceptMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// 1. Ignore messages whose Step field do not match the current logical clock
	if paxosAcceptMsg.Step != n.paxos.GetStep() {
		return xerrors.Errorf("Step %u is not the same as our current step %u", paxosAcceptMsg.Step, n.paxos.GetStep())
	}
	// 2. Ignore messages whose id is not greater than maxID
	if paxosAcceptMsg.ID != n.paxos.GetMaxID() {
		return xerrors.Errorf("The id %u is not greater than the current maxID %u", paxosAcceptMsg.ID, n.paxos.GetMaxID())
	}

	return n.NotifyReceivedAccept(*paxosAcceptMsg, pkt)
}

func (n *node) execTLCMessage(msg types.Message, pkt transport.Packet) error {
	tlcMsg, ok := msg.(*types.TLCMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	// 1. Ignore messages whose Step field do not match the current logical clock
	if tlcMsg.Step < n.paxos.GetStep() {
		return xerrors.Errorf("Step %u is less than our current step %u", tlcMsg.Step, n.paxos.GetStep())
	}

	return n.NotifyReceivedTLC(*tlcMsg, pkt)
}
