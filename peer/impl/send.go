package impl

import (
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"time"
)

func (n *node) SendRumor(source string, dest string, msg transport.Message) error {
	n.log.Println("Send Rumor from ", n.Addr(), " to ", dest)
	pkt, err := n.UnicastComplete(source, dest, msg)
	if err != nil {
		return err
	}

	if n.conf.AckTimeout > 0 {
		n.log.Printf("Send to ack listener to listen to new ack %s for %s\n", pkt.Header.PacketID, pkt.Header.Destination)
		n.ackHandler <- AckTracker{pkt.Header.PacketID, pkt.Header.Destination, msg, time.Now()}
	}
	return nil
}

func (n *node) SendStatusMessage(dest string) error {
	statusMsg := n.GetStatusMessage()
	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(statusMsg)
	if err != nil {
		return err
	}

	return n.Unicast(dest, transportMsg)
}

func (n *node) SendAck(pkt transport.Packet) error {
	n.log.Println("Send ack message to ", pkt.Header.Source, " with packetID ", pkt.Header.PacketID)

	ackMsg := types.AckMessage{AckedPacketID: pkt.Header.PacketID, Status: n.GetStatusMessage()}
	n.log.Println("Status in ack : ", n.GetStatusMessage())
	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(ackMsg)
	if err != nil {
		return err
	}
	return n.UnicastDirect(n.conf.Socket.GetAddress(), pkt.Header.RelayedBy, transportMsg)
}

func (n *node) SendDataRequest(metahash, dest string) (requestId string, err error) {
	dataRequestMsg := types.DataRequestMessage{}.New(metahash)

	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(dataRequestMsg)
	if err != nil {
		return dataRequestMsg.RequestID, err
	}

	err = n.Unicast(dest, transportMsg)
	if err != nil {
		return dataRequestMsg.RequestID, err
	}

	// Open the channel to receive the reply on it
	_, loaded := n.dataReply.LoadOrStore(dataRequestMsg.RequestID, make(chan types.DataReplyMessage))
	if loaded {
		n.log.Printf("While creating the channel to receive the reply on the data request (%s), the channel was already created\n", dataRequestMsg.RequestID)
	}

	return dataRequestMsg.RequestID, nil
}

func (n *node) SendDataReplyMessage(bytes []byte, dataRequestMessage types.DataRequestMessage, dest string) error {
	dataReplyMsg := types.DataReplyMessage{RequestID: dataRequestMessage.RequestID, Key: dataRequestMessage.Key, Value: bytes}

	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(dataReplyMsg)
	if err != nil {
		return err
	}

	err = n.Unicast(dest, transportMsg)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) SendSearchRequestMessage(searchRequestMsg types.SearchRequestMessage, dest string) (string, error) {

	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(searchRequestMsg)
	if err != nil {
		return "", err
	}

	err = n.Unicast(dest, transportMsg)
	if err != nil {
		return "", err
	}

	// Open the channel to receive the reply on it
	_, loaded := n.searchReply.LoadOrStore(searchRequestMsg.RequestID, make(chan types.SearchReplyMessage))
	if loaded {
		n.log.Printf("While creating the channel to receive the reply on the search request (%s), the channel was already created\n", searchRequestMsg.RequestID)
	}

	return searchRequestMsg.RequestID, nil
}

func (n *node) SendSearchReplyMessage(names []string, searchRequestMsg types.SearchRequestMessage) error {
	allFilesInfo := make([]types.FileInfo, 0)

	for _, name := range names {
		metahash := n.Resolve(name)

		chunks, err := n.localChunksDownload(metahash)
		if err != nil {
			return err
		}

		allFilesInfo = append(allFilesInfo, types.FileInfo{
			Name:     name,
			Metahash: metahash,
			Chunks:   chunks,
		})
	}

	searchReplyMsg := types.SearchReplyMessage{
		RequestID: searchRequestMsg.RequestID,
		Responses: allFilesInfo,
	}

	transportMsg, err := n.conf.MessageRegistry.MarshalMessage(searchReplyMsg)
	if err != nil {
		return err
	}

	// err = n.UnicastDirect(n.conf.Socket.GetAddress(), searchRequestMsg.Origin, transportMsg)
	err = n.UnicastDirect(n.conf.Socket.GetAddress(), searchRequestMsg.Origin, transportMsg)
	if err != nil {
		return err
	}

	return nil
}
