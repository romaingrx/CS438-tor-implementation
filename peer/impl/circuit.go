package impl

import (
	"fmt"
	"go.dedis.ch/cs438/crypto"
	"sort"
	"strings"
	"time"

	"github.com/rs/xid"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
)

func (n *node) AddNodeToDirectory(name string, info NodeInfo) error {
	if !n.directory.Add(name, info) {
		return xerrors.Errorf("Node %s already in the directory", name)
	}
	return nil
}

func (n *node) AddNodesToDirectory(nodesInfo map[string]NodeInfo) error {
	var errors []string
	for name, info := range nodesInfo {
		if err := n.AddNodeToDirectory(name, info); err != nil {
			errors = append(errors, fmt.Sprintf("%v", err))
		}
	}

	return xerrors.Errorf("%s", strings.Join(errors, "\n"))
}

// CreateCircuit will construct and exchange keys with the nodes
func (n *node) CreateCircuit(circuitId string, nodes []string) error {
	// In this function we need to compute a shared key with every node on the circuit, to do so, we need to send a
	// KeyExchangeMessage with the first node, then encrypt the KeyExchangeMessage of the second node with the shared
	// key of the first, ...
	// self =======================================================================        node1       =======================================  node2  === ...
	//      --- KeyExhangeRequestMessage(Pk1) ------------------------------------->
	//     <--- KeyExhangeRequestMessage(Sk1, sign1) ------------------------------
	//      --- OnionLayerMessage(Encrypt(KeyExhangeRequestMessage(Pk2), Sk1))  ---> Decrypt(..., Sk1) ---- KeyExhangeRequestMessage(Pk2)  --->
	//     <--- OnionLayerMessage(Encrypt(KeyExhangeResponseMessage(Sk2), Sk1)) <--- Encrypt(..., Sk1) <--- KeyExhangeResponseMessage(Sk2) ---
	// ...

	var circuit Circuit
	for idx, nod := range nodes {
		// First generate a private, public key for this particular node
		KeyExchangeAlgo := crypto.DiffieHellman{}
		Pk, err := KeyExchangeAlgo.GenerateParameters()
		if err != nil {
			return err
		}

		msg := types.KeyExchangeRequestMessage{
			Parameters: Pk,
		}
		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(msg)
		if err != nil {
			return err
		}

		// Send the KeyExhangeRequestMessage through the nodes preceding node n
		if 0 < idx {
			// TODO tor: verify the packing is working
			onion, err := n.PackOnionLayersUntil(msg, circuitId, nodes[:idx], nod)
			if err != nil {
				return err
			}
			transportMsg, err = n.conf.MessageRegistry.MarshalMessage(onion)
			if err != nil {
				return err
			}
		}

		err = n.UnicastDirect(n.conf.Socket.GetAddress(), nod, transportMsg)
		if err != nil {
			return err
		}

		select {
		case msg := <-*n.keyExchangeChan.Get(circuitId):
			if reply, ok := msg.(types.KeyExchangeResponseMessage); ok {
				if !n.VerifyKeyExchangeResponse(nod, reply) {
					return xerrors.Errorf("Failed to verify the signature of a key exchange response from node %s", nod)
				}
				if !KeyExchangeAlgo.HandleAndVerifyNegotiation(reply.Parameters, reply.PreMasterSecret) {
					return xerrors.Errorf("Failed to verify the pre master secret response from node %s", nod)
				}

				// If every test passes, then add this node and the master secret in the circuit
				circuit.Extend(nod, KeyExchangeAlgo.GetMasterSecret())
			} else if reply, ok := msg.(types.KeyExchangeAbandonMessage); ok {
				n.DropCircuit(circuitId)
				return xerrors.Errorf("Abandon of the circuit %s : %s", reply.CircuitId, reply.Extra)
			} else {
				n.DropCircuit(circuitId)
				return xerrors.Errorf("Wrong type message %s received on the keyExchange channel for circuitId %s", msg.Name, circuitId)
			}
			// TODO tor: add a timeout
		}

	}
	n.circuits.Put(circuitId, circuit)
	return nil
}

func (n *node) PackOnionLayersUntil(msg types.Message, circuitId string, nodes []string, to string) (*types.OnionLayerMessage, error) {
	circuit := n.circuits.Get(circuitId)
	var onion types.OnionLayerMessage
	for idx, _ := range nodes {
		// We reached the last node and thus do not want to encrypt anything
		nod := nodes[len(nodes)-idx-1]

		sharedKey := circuit.sharedKey[nod]
		if sharedKey == nil {
			return &types.OnionLayerMessage{}, xerrors.Errorf("Do not find a shared key for node %s when encrypting the onion", nod)
		}

		encryptedMsg, err := crypto.EncryptMsg(sharedKey, msg)
		if err != nil {
			return &types.OnionLayerMessage{}, err
		}

		cto := to
		if idx > 0 {
			cto = nodes[len(nodes)-idx]
		}

		onion = types.OnionLayerMessage{
			CircuitId: circuitId,
			Direction: types.OnionLayerForward,
			To:        cto,
			Type:      msg.Name(),
			Payload:   encryptedMsg,
		}

		msg = onion
	}
	return &onion, nil
}

func (n *node) VerifyKeyExchangeResponse(nod string, reply types.KeyExchangeResponseMessage) bool {
	panic("implement me")
}

func (n *node) HandleExchangeKey(uid string, from string, publicKey []byte) error {
	panic("implement me")
}

// Circuit Selection
func (n *node) CalculateCircuitsMetrics() {

	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()
	for _, circuit := range n.proxyCircuits {
		if circuit.associatedMessage != nil {
			continue // Skip if circuit already in use
		}

		if time.Since(circuit.lastMetricTimestamp) < n.conf.MetricMessageRetry {
			continue // Skip if time elapsed since last metric request is less than retry threshold
		}

		metricRequest := types.RelayMetricRequestMessage{
			CircuitId: circuit.id,
			UID:       xid.New().String(),
		}

		metricsReqMsg, err := n.conf.MessageRegistry.MarshalMessage(metricRequest)
		if err != nil {
			n.log.Printf("Error marshaling metric request for circuit id %s\n", metricRequest.CircuitId)
			return
		}

		err = n.UnicastDirect(n.conf.Socket.GetAddress(), circuit.secondNode.IP, metricsReqMsg)
		if err != nil {
			n.log.Printf("Error sending metric request for circuit id %s\n", metricRequest.CircuitId)
			return
		}

		circuit.lastMetricMessage = metricRequest.UID
		circuit.lastMetricTimestamp = time.Now()
	}

}

func (n *node) getRelayCircuit(uid string) *RelayCircuit {
	n.relaysLock.Lock()
	defer n.relaysLock.Unlock()

	for _, circuit := range n.relayCircuits {
		if circuit.id == uid {
			return circuit
		}
	}

	return nil
}

func (n *node) getProxyCircuit(circuitId string) *ProxyCircuit {
	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()

	for _, circuit := range n.proxyCircuits {
		if circuit.id == circuitId {
			return circuit
		}
	}

	return nil
}

func (n *node) DropCircuit(circuitId string) {
	n.circuits.Delete(circuitId)
}

func (n *node) ExecRelayMetricRequestMessage(msg types.Message, pkt transport.Packet) error {

	// Message received could be received either at relay node or exit node
	// In case of relay node, for example circuit id will be c1,
	// this node has to find c2, update circuit id for the message with this id
	// then forward the message to c2's second node since first node is already the relay node
	// In case of exit node, for example c2, nextCircuit will be null
	// Exit node then uses c2's first node to return message with same circuit id and uid for message

	metricRequestMsg, ok := msg.(*types.RelayMetricRequestMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	relayCircuit := n.getRelayCircuit(metricRequestMsg.CircuitId)

	if relayCircuit == nil {
		return xerrors.Errorf("Cannot find circuit %s requested for metrics\n", metricRequestMsg.CircuitId)
	}

	// If this is exit node, then send back response
	if relayCircuit.nextCircuit == nil {
		metricResponse := types.RelayMetricResponseMessage{
			CircuitId: metricRequestMsg.CircuitId,
			UID:       metricRequestMsg.UID,
		}

		metricsResponseMsg, err := n.conf.MessageRegistry.MarshalMessage(metricResponse)
		if err != nil {
			return xerrors.Errorf("Error marshaling metric response for circuit id %s\n", metricResponse.CircuitId)
		}

		err = n.UnicastDirect(n.conf.Socket.GetAddress(), relayCircuit.firstNode.IP, metricsResponseMsg)
		if err != nil {
			return xerrors.Errorf("Error sending metric request for circuit id %s\n", metricResponse.CircuitId)
		}

		return nil
	}

	// If this is a relay node then forward message

	// Update Circuit Id to be the next circuit id
	metricRequestMsg.CircuitId = relayCircuit.nextCircuit.id
	metricsRequestMsg, err := n.conf.MessageRegistry.MarshalMessage(metricRequestMsg)
	if err != nil {
		return xerrors.Errorf("Error marshaling metric Request for circuit id %s\n", metricRequestMsg.CircuitId)
	}

	err = n.UnicastDirect(n.conf.Socket.GetAddress(), relayCircuit.nextCircuit.secondNode.IP, metricsRequestMsg)
	if err != nil {
		return xerrors.Errorf("Error forwarding metric request for circuit id %s\n", metricRequestMsg.CircuitId)
	}

	return nil
}

func (n *node) ExecRelayMetricResponseMessage(msg types.Message, pkt transport.Packet) error {

	metricResponseMsg, ok := msg.(*types.RelayDataResponseMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	relayCircuit := n.getRelayCircuit(metricResponseMsg.CircuitId)
	var proxyCircuit *ProxyCircuit
	if relayCircuit == nil {
		proxyCircuit = n.getProxyCircuit(metricResponseMsg.CircuitId)
	}

	if relayCircuit == nil && proxyCircuit == nil {
		return xerrors.Errorf("Cannot find circuit %s for metrics response\n", metricResponseMsg.CircuitId)
	}

	if relayCircuit != nil {
		// Message received by a relay node
		// Forward it to previous circuit

		// Update Circuit Id to be the next circuit id
		metricResponseMsg.CircuitId = relayCircuit.beforeCircuit.id
		metricsResponseMsg, err := n.conf.MessageRegistry.MarshalMessage(metricResponseMsg)
		if err != nil {
			return xerrors.Errorf("Error marshaling metric Request for circuit id %s\n", metricResponseMsg.CircuitId)
		}

		err = n.UnicastDirect(n.conf.Socket.GetAddress(), relayCircuit.beforeCircuit.firstNode.IP, metricsResponseMsg)
		if err != nil {
			return xerrors.Errorf("Error forwarding metric request for circuit id %s\n", metricResponseMsg.CircuitId)
		}

		return nil
	}

	// If this is the original proxy node then just call RTT received marking the round trip complete
	n.RTT_Received(metricResponseMsg)
	return nil
}

func (n *node) RTT_Received(metricsResponseMessage *types.RelayDataResponseMessage) {

	proxyCircuit := n.getProxyCircuit(metricsResponseMessage.CircuitId)

	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()

	if proxyCircuit.lastMetricMessage != metricsResponseMessage.UID {
		return // Metrics Message isn't the same!
	}

	proxyCircuit.currentRtt = time.Since(proxyCircuit.lastMetricTimestamp)
	if proxyCircuit.rttMin == nil {
		proxyCircuit.rttMin = new(time.Duration)
		*proxyCircuit.rttMin = proxyCircuit.currentRtt
		return // No need to calculate congestion if this is the first trip
	}

	currentCtt := proxyCircuit.currentRtt - *proxyCircuit.rttMin
	if len(proxyCircuit.ctt) < 5 {
		proxyCircuit.ctt = append(proxyCircuit.ctt, currentCtt)
	} else {
		proxyCircuit.ctt = append(proxyCircuit.ctt[1:], currentCtt)
	}

	var total float64 = 0
	for _, val := range proxyCircuit.ctt {
		total += float64(val)
	}

	proxyCircuit.cttAverage = time.Duration((total) / float64(len(proxyCircuit.ctt)))

}

func (n *node) PerformCircuitSelectionBackground() {

	// Every X minutes, each circuit gets sent a message that
	// aids in calculating the RTT
	ticker := time.NewTicker(n.conf.MetricMessageInterval)
	n.circuitSelectionQuit = make(chan struct{})

	go func() {
		for {
			select {
			case <-ticker.C:
				n.CalculateCircuitsMetrics()
			case <-n.circuitSelectionQuit:
				ticker.Stop()
				return
			}
		}
	}()

}

func (n *node) SelectCircuitRTT() *ProxyCircuit {
	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()

	if len(n.proxyCircuits) < 1 {
		return nil
	} else if len(n.proxyCircuits) == 1 {
		return n.proxyCircuits[0]
	}

	circuits := make([]*ProxyCircuit, len(n.proxyCircuits))
	copy(circuits, n.proxyCircuits)

	sort.SliceStable(circuits, func(i, j int) bool {
		return circuits[i].currentRtt < circuits[j].currentRtt
	})

	return n.proxyCircuits[0]
}

func (n *node) SelectCircuitCT() *ProxyCircuit {
	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()

	if len(n.proxyCircuits) < 1 {
		return nil
	} else if len(n.proxyCircuits) == 1 {
		return n.proxyCircuits[0]
	}

	circuits := make([]*ProxyCircuit, len(n.proxyCircuits))
	copy(circuits, n.proxyCircuits)

	sort.SliceStable(circuits, func(i, j int) bool {
		return circuits[i].cttAverage < circuits[j].cttAverage
	})

	return n.proxyCircuits[0]
}

func (n *node) SelectCircuitCTRTT() *ProxyCircuit {
	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()

	if len(n.proxyCircuits) < 1 {
		return nil
	} else if len(n.proxyCircuits) == 1 {
		return n.proxyCircuits[0]
	}

	circuits := make([]*ProxyCircuit, len(n.proxyCircuits))
	copy(circuits, n.proxyCircuits)

	// Sort by CT first then for the first 2 choose the one with lowest RTT
	sort.SliceStable(circuits, func(i, j int) bool {
		return circuits[i].cttAverage < circuits[j].cttAverage
	})

	if circuits[0].currentRtt < circuits[1].currentRtt {
		return n.proxyCircuits[0]
	}

	return n.proxyCircuits[1]
}

func (n *node) SelectCircuitRTTCT() *ProxyCircuit {
	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()

	if len(n.proxyCircuits) < 1 {
		return nil
	} else if len(n.proxyCircuits) == 1 {
		return n.proxyCircuits[0]
	}

	circuits := make([]*ProxyCircuit, len(n.proxyCircuits))
	copy(circuits, n.proxyCircuits)

	// Sort by RTT first then for the first 2 choose the one with lowest CT
	sort.SliceStable(circuits, func(i, j int) bool {
		return circuits[i].currentRtt < circuits[j].currentRtt
	})

	if circuits[0].cttAverage < circuits[1].cttAverage {
		return n.proxyCircuits[0]
	}

	return n.proxyCircuits[1]
}

func (n *node) SelectCircuit(request *RelayHttpRequest) *ProxyCircuit {
	var proxy *ProxyCircuit

	switch n.conf.CircuitSelectAlgo {
	case peer.RTT:
		proxy = n.SelectCircuitRTT()
	case peer.CTT:
		proxy = n.SelectCircuitCT()
	case peer.RTT_CT:
		proxy = n.SelectCircuitRTTCT()
	case peer.CT_RTT:
		proxy = n.SelectCircuitCTRTT()
	}

	if proxy == nil {
		return nil
	}

	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()

	proxy.associatedMessage = request
	return proxy
}

// End Circuit Selection

// Messages/Data Relay

func (n *node) ExecRelayDataRequestMessage(msg types.Message, pkt transport.Packet) error {

	return nil
}

func (n *node) ExecRelayDataResponseMessage(msg types.Message, pkt transport.Packet) error {

	return nil
}

func (n *node) DataReceived() {
}

func (n *node) SendMessage() {
}

// End Messages/Data Relay
