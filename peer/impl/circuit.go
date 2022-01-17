package impl

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rs/xid"
	"go.dedis.ch/cs438/crypto"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
)

func (n *node) AddNodeToDirectory(name string, info NodeInfo, update bool) error {
	if !n.directory.Add(name, info) && !update {
		return xerrors.Errorf("Node %s already in the directory", name)
	}
	return nil
}

func (n *node) AddNodesToDirectory(nodesInfo map[string]NodeInfo) error {
	var errs []string
	for name, info := range nodesInfo {
		if err := n.AddNodeToDirectory(name, info, false); err != nil {
			errs = append(errs, fmt.Sprintf("%v", err))
		}
	}

	return xerrors.Errorf("%s", strings.Join(errs, "\n"))
}

// CreateRandomCircuit will construct and exchange keys with random nodes
func (n *node) CreateRandomCircuit() error {
	// TODO tor: check that this all nodes are different
	nodes, err := n.directory.GetRandom(3, []string{n.conf.Socket.GetAddress()})
	if err != nil {
		return err
	}
	return n.CreateCircuit(nodes)
}

// CreateCircuit will construct and exchange keys with the nodes
func (n *node) CreateCircuit(nodes []string) error {
	// In this function we need to compute a shared key with every node on the circuit, to do so, we need to send a
	// KeyExchangeMessage with the first node, then encrypt the KeyExchangeMessage of the second node with the shared
	// key of the first, ...
	// self =======================================================================        node1       =======================================  node2  === ...
	//      --- KeyExchangeRequestMessage(Pk1) ------------------------------------->
	//     <--- KeyExchangeRequestMessage(Sk1, sign1) ------------------------------
	//      --- OnionLayerMessage(Encrypt(KeyExchangeRequestMessage(Pk2), Sk1))  ---> Decrypt(..., Sk1) ---- KeyExchangeRequestMessage(Pk2)  --->
	//     <--- OnionLayerMessage(Encrypt(KeyExchangeResponseMessage(Sk2), Sk1)) <--- Encrypt(..., Sk1) <--- KeyExchangeResponseMessage(Sk2) ---
	// ...
	startTime := time.Now()

	proxyCircuit := NewProxyCircuit(
		xid.New().String(),
		n.directory.GetNodeInfo(n.conf.Socket.GetAddress()),
		n.directory.GetNodeInfo(nodes[0]),
	)
	// fmt.Println("Initial circuit id ", proxyCircuit.id)
	err := n.addProxyCircuit(proxyCircuit)
	if err != nil {
		return err
	}

	for idx, nod := range nodes {
		// First generate a private, public key for this particular node
		KeyExchangeAlgo := crypto.DiffieHellman{}
		Pk, err := KeyExchangeAlgo.GenerateParameters()
		if err != nil {
			return err
		}

		msg := types.KeyExchangeRequestMessage{
			CircuitId:  proxyCircuit.id,
			Parameters: Pk,
		}

		if idx > 0 {
			msg.Extend = nod
		}

		onion, err := PackProxyOnionLayers(msg, *proxyCircuit)
		if err != nil {
			return err
		}

		transportMsg, err := n.conf.MessageRegistry.MarshalMessage(onion)
		if err != nil {
			return err
		}

		err = n.UnicastDirect(n.conf.Socket.GetAddress(), proxyCircuit.secondNode.IP, transportMsg)
		if err != nil {
			return err
		}

		select {
		case msg := <-*n.keyExchangeChan.Get(proxyCircuit.id):
			// fmt.Printf("Received key exchange response on the channel %s\n", proxyCircuit.id)
			if reply, ok := msg.(types.KeyExchangeResponseMessage); ok {
				if !n.VerifyKeyExchangeResponse(nod, reply) {
					return xerrors.Errorf("Failed to verify the signature of a key exchange response from node %s", nod)
				}
				// fmt.Printf("Verified key exchange response on the channel %s\n", proxyCircuit.id)
				KeyExchangeAlgo.HandleNegotiation(reply.Parameters)

				// If every test passes, then add this node and the master secret in the circuit and continue
				proxyCircuit.AllMasterSecrets = append(proxyCircuit.AllMasterSecrets, KeyExchangeAlgo.GetMasterSecret())
			} else {
				n.deleteProxyCircuit(proxyCircuit.id)
				return xerrors.Errorf("Wrong type message %s received on the keyExchange channel for circuitId %s", msg.Name, proxyCircuit.id)
			}
			// TODO tor: add a timeout
		}

	}

	fmt.Printf("Proxy Circuit Created with id %s and nodes %s in %f seconds\n", proxyCircuit.id, nodes, time.Since(startTime).Seconds())
	return n.addProxyCircuit(proxyCircuit)
}

func EncryptProxy(proxy ProxyCircuit, payload []byte) ([]byte, error) {

	var err error
	for reverseIdx := range proxy.AllMasterSecrets {
		masterSecret := proxy.AllMasterSecrets[len(proxy.AllMasterSecrets)-reverseIdx-1]
		payload, err = crypto.Encrypt(masterSecret, payload)
		if err != nil {
			return nil, err
		}
	}

	return payload, nil
}

func DecryptProxy(proxy ProxyCircuit, payload []byte) ([]byte, error) {
	var err error

	for _, masterSecret := range proxy.AllMasterSecrets {
		payload, err = crypto.Decrypt(masterSecret, payload)
		if err != nil {
			return nil, err
		}
	}

	return payload, nil
}

func EncryptRelay(relay RelayCircuit, payload []byte) ([]byte, error) {
	var err error
	if relay.masterSecret != nil {
		payload, err = crypto.Encrypt(relay.masterSecret, payload)
		if err != nil {
			return nil, err
		}
	}
	return payload, nil
}

func DecryptRelay(relay RelayCircuit, payload []byte) ([]byte, error) {

	var err error
	if relay.masterSecret != nil {
		payload, err = crypto.Decrypt(relay.masterSecret, payload)
		if err != nil {
			return nil, err
		}
	}
	return payload, nil

}
func PackProxyOnionLayers(msg types.Message, proxyCircuit ProxyCircuit) (*types.OnionLayerMessage, error) {
	var err error
	msgBytes, err := json.Marshal(msg)
	onion := types.OnionLayerMessage{
		CircuitId: proxyCircuit.id,
		Direction: types.OnionLayerForward,
		Type:      msg.Name(),
		Payload:   msgBytes,
	}

	for reverseIdx := range proxyCircuit.AllMasterSecrets {
		masterSecret := proxyCircuit.AllMasterSecrets[len(proxyCircuit.AllMasterSecrets)-reverseIdx-1]
		onion.Payload, err = crypto.Encrypt(masterSecret, onion.Payload)
		if err != nil {
			return nil, err
		}
	}

	return &onion, nil
}

func UnpeelProxyOnionLayers(onion types.OnionLayerMessage, proxyCircuit ProxyCircuit) ([]byte, error) {
	var err error

	for _, masterSecret := range proxyCircuit.AllMasterSecrets {
		onion.Payload, err = crypto.Decrypt(masterSecret, onion.Payload)
		if err != nil {
			return nil, err
		}
	}

	return onion.Payload, nil
}

func PackRelayExitOnionLayer(msg types.Message, relayCircuit RelayCircuit) (*types.OnionLayerMessage, error) {
	var err error
	msgBytes, err := json.Marshal(msg)
	onion := types.OnionLayerMessage{
		CircuitId: relayCircuit.id,
		Direction: types.OnionLayerBackward,
		Type:      msg.Name(),
		Payload:   msgBytes,
	}
	if relayCircuit.masterSecret != nil {
		onion.Payload, err = crypto.Encrypt(relayCircuit.masterSecret, onion.Payload)
		if err != nil {
			return nil, err
		}
	}

	return &onion, nil
}

func PackRelayOnionLayer(onion types.OnionLayerMessage, relayCircuit RelayCircuit) ([]byte, error) {
	var err error
	if relayCircuit.masterSecret != nil {
		onion.Payload, err = crypto.Encrypt(relayCircuit.masterSecret, onion.Payload)
		if err != nil {
			return nil, err
		}
	}
	return onion.Payload, nil
}

func UnpeelRelayOnionLayer(onion types.OnionLayerMessage, relayCircuit RelayCircuit) ([]byte, error) {
	var err error
	if relayCircuit.masterSecret != nil {
		onion.Payload, err = crypto.Decrypt(relayCircuit.masterSecret, onion.Payload)
		if err != nil {
			return nil, err
		}
	}
	return onion.Payload, nil
}

// func (n *node) DEPERECATEDPackOnionLayersUntil(msg types.Message, circuitIds []string, nodes []string, masterSecrets [][]byte, to string) (*types.OnionLayerMessage, error) {
// 	var onion types.OnionLayerMessage
// 	for idx, _ := range nodes {
// 		// We reached the last node and thus do not want to encrypt anything
// 		reverseIdx := len(nodes) - idx - 1
// 		circuitId := circuitIds[reverseIdx]
// 		masterSecret := masterSecrets[reverseIdx]
//
// 		encryptedMsg, err := EncryptMsg(masterSecret, msg)
// 		if err != nil {
// 			return &types.OnionLayerMessage{}, err
// 		}
//
// 		cto := to
// 		if idx > 0 {
// 			cto = nodes[len(nodes)-idx]
// 		}
//
// 		onion = types.OnionLayerMessage{
// 			CircuitId: circuitId,
// 			Direction: types.OnionLayerForward,
// 			To:        cto,
// 			Type:      msg.Name(),
// 			Payload:   encryptedMsg,
// 		}
//
// 		msg = onion
// 	}
// 	return &onion, nil
// }

func GetBytesToSign(response types.KeyExchangeResponseMessage) []byte {
	return response.Parameters
}

func (n *node) SignKeyExchangeResponse(key *rsa.PrivateKey, response types.KeyExchangeResponseMessage) ([]byte, error) {
	return crypto.Sign(GetBytesToSign(response), key)
}

func (n *node) VerifyKeyExchangeResponse(nod string, reply types.KeyExchangeResponseMessage) bool {
	pk := n.directory.GetPublicKey(nod)
	return crypto.Verify(GetBytesToSign(reply), reply.Signature, pk)
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

		metricBody := types.RelayMetricBody{
			UID: xid.New().String(),
		}

		payload, err := json.Marshal(metricBody)
		if err != nil {
			continue
		}

		newPayload, err := EncryptProxy(*circuit, payload)
		if err != nil {
			continue
		}

		metricRequest := types.RelayMetricRequestMessage{
			CircuitId: circuit.id,
			Payload:   newPayload,
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

		circuit.lastMetricMessage = metricBody.UID
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

func (n *node) deleteProxyCircuit(circuitId string) bool {
	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()

	var idx = -1
	for run, circuit := range n.proxyCircuits {
		if circuit.id == circuitId {
			idx = run
			break
		}
	}

	if idx == -1 {
		return false
	}

	n.proxyCircuits = append(n.proxyCircuits[:idx], n.proxyCircuits[idx+1:]...)
	return true
}

func (n *node) addProxyCircuit(circuit *ProxyCircuit) error {
	if n.getProxyCircuit(circuit.id) != nil {
		return xerrors.Errorf("The circuitId %s is already in the proxy circuits", circuit.id)
	}
	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()
	n.proxyCircuits = append(n.proxyCircuits, circuit)
	return nil
}

func (n *node) addRelayCircuit(circuit *RelayCircuit) error {
	if n.getRelayCircuit(circuit.id) != nil {
		return xerrors.Errorf("The circuitId %s is already in the relay circuits", circuit.id)
	}
	n.relaysLock.Lock()
	defer n.relaysLock.Unlock()
	n.relayCircuits = append(n.relayCircuits, circuit)
	return nil
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

	decryptedPayload, err := DecryptRelay(*relayCircuit, metricRequestMsg.Payload)

	if err != nil {
		return errors.New(fmt.Sprint("Couldn't decrypt relay metric request message with circuit id %s", metricRequestMsg.CircuitId))
	}

	// If this is exit node, then send back response
	if relayCircuit.nextCircuit == nil {

		// Use Encrypted body
		metricResponse := types.RelayMetricResponseMessage{
			CircuitId: metricRequestMsg.CircuitId,
			Payload:   metricRequestMsg.Payload,
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
	metricRequestMsg.Payload = decryptedPayload
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

	metricResponseMsg, ok := msg.(*types.RelayMetricResponseMessage)
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

		//Encrypt it first
		encryptedMsg, err := EncryptRelay(*relayCircuit.beforeCircuit, metricResponseMsg.Payload)
		if err != nil {
			return errors.New(fmt.Sprint("Couldn't encrypt relay metric response message with circuit id %s", metricResponseMsg.CircuitId))
		}

		// Update Circuit Id to be the next circuit id
		metricResponseMsg.CircuitId = relayCircuit.beforeCircuit.id
		metricResponseMsg.Payload = encryptedMsg
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

func (n *node) RTT_Received(metricsResponseMessage *types.RelayMetricResponseMessage) {

	proxyCircuit := n.getProxyCircuit(metricsResponseMessage.CircuitId)

	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()

	metricBodyBytes, err := DecryptProxy(*proxyCircuit, metricsResponseMessage.Payload)
	if err != nil {
		n.log.Printf("Couldn't decrypt proxy metric response message with circuit id %s", metricsResponseMessage.CircuitId)
	}

	var metricsBody types.RelayMetricBody
	err = json.Unmarshal(metricBodyBytes, &metricsBody)
	if err != nil {
		n.log.Printf("Couldn't unmarshall proxy metric response message with circuit id %s", metricsResponseMessage.CircuitId)
	}

	if proxyCircuit.lastMetricMessage != metricsBody.UID {
		return // Metrics Message isn't the same!
	}

	proxyCircuit.currentRtt = time.Since(proxyCircuit.lastMetricTimestamp)
	if proxyCircuit.rttMin == nil {
		proxyCircuit.rttMin = new(time.Duration)
		*(proxyCircuit.rttMin) = proxyCircuit.currentRtt
		return // No need to calculate congestion if this is the first trip
	} else {
		if *(proxyCircuit.rttMin) > proxyCircuit.currentRtt {
			*(proxyCircuit.rttMin) = proxyCircuit.currentRtt
		}
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

	if total != 0 {
		proxyCircuit.cttAverage = time.Duration((total) / float64(len(proxyCircuit.ctt)))
	}

	n.PrintProxyMetrics(proxyCircuit)

}

func (n *node) PrintProxyMetrics(proxy *ProxyCircuit) {
	fmt.Printf("Circuit %s has rtt_min %d, rtt_current %d, ctt_avg %d\n", proxy.id, *proxy.rttMin, proxy.currentRtt, proxy.cttAverage)
}

func (n *node) PerformCircuitCreationBackground() {
	go func() {
		for {
			nCircuits := n.GetNumberOfProxyCircuits()
			// fmt.Println("Number of circuit ", nCircuits)
			// fmt.Println("Maximum number of circuit ", n.conf.MaximumCircuits)
			if nCircuits < n.conf.MaximumCircuits {
				for i := 0; i < n.conf.MaximumCircuits-nCircuits; i++ {
					// fmt.Println("Create a circuit")
					n.CreateRandomCircuit()
				}
			}

			time.Sleep(n.conf.CircuitUpdateTicker)
		}
	}()
}

func (n *node) PerformCircuitDeletionBackground() {
	go func() {
		time.Sleep(120 * time.Second)
		for {
			n.proxiesLock.Lock()
			nCircuits := n.GetNumberOfProxyCircuits()
			if nCircuits > n.conf.MinimumCircuits {
				circuits := n.GetAllProxyCircuitsSorted(func(circuitIdx1, circuitIdx2 int) bool {
					return n.proxyCircuits[circuitIdx1].lastUsed.Before(n.proxyCircuits[circuitIdx2].lastUsed)
				}, false)
				for i := 1; i < n.conf.MinimumCircuits-nCircuits; i++ {
					if time.Now().Sub(circuits[i].lastUsed) > n.conf.LastUsedUnvalid && len(circuits[i].associatedMessage) == 0 {
						n.deleteProxyCircuit(circuits[i].id)
					}
				}
			}
			n.proxiesLock.Unlock()

			time.Sleep(n.conf.CircuitUpdateTicker)
		}
	}()
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
	}

	circuits := make([]*ProxyCircuit, len(n.proxyCircuits))
	copy(circuits, n.proxyCircuits)

	var filtered []*ProxyCircuit
	for _, proxy := range circuits {
		if len(proxy.associatedMessage) < 5 {
			filtered = append(filtered, proxy)
		}
	}

	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].currentRtt < filtered[j].currentRtt
	})

	if len(filtered) < 1 {
		return nil
	}

	return filtered[0]
}

func (n *node) SelectCircuitCT() *ProxyCircuit {
	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()

	if len(n.proxyCircuits) < 1 {
		return nil
	}

	circuits := make([]*ProxyCircuit, len(n.proxyCircuits))
	copy(circuits, n.proxyCircuits)

	var filtered []*ProxyCircuit
	for _, proxy := range circuits {
		if len(proxy.associatedMessage) < 5 {
			filtered = append(filtered, proxy)
		}
	}

	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].cttAverage < filtered[j].cttAverage
	})

	if len(filtered) < 1 {
		return nil
	}

	return filtered[0]
}

func (n *node) SelectCircuitCTRTT() *ProxyCircuit {
	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()

	if len(n.proxyCircuits) < 1 {
		return nil
	}

	circuits := make([]*ProxyCircuit, len(n.proxyCircuits))
	copy(circuits, n.proxyCircuits)

	var filtered []*ProxyCircuit
	for _, proxy := range circuits {
		if len(proxy.associatedMessage) < 5 {
			filtered = append(filtered, proxy)
		}
	}

	// Sort by CT first then for the first 2 choose the one with lowest RTT
	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].cttAverage < filtered[j].cttAverage
	})

	if len(filtered) < 1 {
		return nil
	}

	if len(filtered) == 1 {
		return filtered[0]
	}

	if filtered[0].currentRtt < filtered[1].currentRtt {
		return filtered[0]
	}

	return filtered[1]
}

func (n *node) SelectCircuitRTTCT() *ProxyCircuit {
	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()

	if len(n.proxyCircuits) < 1 {
		return nil
	}

	circuits := make([]*ProxyCircuit, len(n.proxyCircuits))
	copy(circuits, n.proxyCircuits)

	var filtered []*ProxyCircuit
	for _, proxy := range circuits {
		if len(proxy.associatedMessage) < 5 {
			filtered = append(filtered, proxy)
		}
	}

	// Sort by RTT first then for the first 2 choose the one with lowest CT
	sort.SliceStable(filtered, func(i, j int) bool {
		return filtered[i].currentRtt < filtered[j].currentRtt
	})

	if len(filtered) < 1 {
		return nil
	}

	if len(filtered) == 1 {
		return filtered[0]
	}

	if filtered[0].cttAverage < filtered[1].cttAverage {
		return filtered[0]
	}

	return filtered[1]
}

func (n *node) SelectCircuit(request *types.RelayHttpRequest) *ProxyCircuit {
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

	proxy.associatedMessage = append(proxy.associatedMessage, request)
	proxy.lastUsed = time.Now()
	return proxy
}

func (n *node) RemoveProxyMessage(proxy *ProxyCircuit, request *types.RelayHttpRequest) {
	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()

	for i, req := range proxy.associatedMessage {
		if req == request {
			if len(proxy.associatedMessage) < 2 {
				proxy.associatedMessage = make([]*types.RelayHttpRequest, 0)
			} else {
				proxy.associatedMessage[i] = proxy.associatedMessage[len(proxy.associatedMessage)-1]
				proxy.associatedMessage = proxy.associatedMessage[:len(proxy.associatedMessage)-1]
			}
			return
		}
	}
}

// End Circuit Selection

// Messages/Data Relay

func (n *node) ExecRelayDataRequestMessage(msg types.Message, pkt transport.Packet) error {

	// Message received could be received either at relay node or exit node
	// In case of relay node, for example circuit id will be c1,
	// this node has to find c2, update circuit id for the message with this id
	// then forward the message to c2's second node since first node is already the relay node
	// In case of exit node, for example c2, node connects to http server, wait for response and then sends back the result
	// Exit node then uses c2's first node to return message with same circuit id and uid for message

	dataRequestMsg, ok := msg.(*types.RelayDataRequestMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	relayCircuit := n.getRelayCircuit(dataRequestMsg.CircuitId)

	if relayCircuit == nil {
		return xerrors.Errorf("Cannot find circuit %s requested for datas\n", dataRequestMsg.CircuitId)
	}

	decryptedPayload, err := DecryptRelay(*relayCircuit, dataRequestMsg.Payload)
	if err != nil {
		return xerrors.Errorf("Error decrypting data Request for circuit id %s\n", dataRequestMsg.CircuitId)
	}

	fmt.Printf("Received Data Request Message with Circuit id %s", dataRequestMsg.CircuitId)

	if relayCircuit.nextCircuit != nil {
		// If this is a relay node then forward message

		// Update Circuit Id to be the next circuit id
		dataRequestMsg.CircuitId = relayCircuit.nextCircuit.id
		dataRequestMsg.Payload = decryptedPayload
		RequestMsg, err := n.conf.MessageRegistry.MarshalMessage(dataRequestMsg)
		if err != nil {
			return xerrors.Errorf("Error marshaling data Request for circuit id %s\n", dataRequestMsg.CircuitId)
		}

		err = n.UnicastDirect(n.conf.Socket.GetAddress(), relayCircuit.nextCircuit.secondNode.IP, RequestMsg)
		if err != nil {
			return xerrors.Errorf("Error forwarding data request for circuit id %s\n", dataRequestMsg.CircuitId)
		}

		return nil
	}

	// If this is exit node, then send message to http server
	// After receiving the result, send back response

	var messageBody types.RelayDataRequestBody
	err = json.Unmarshal(decryptedPayload, &messageBody)
	if err != nil {
		return xerrors.Errorf("Error unmarshaling data Request for circuit id %s\n", dataRequestMsg.CircuitId)
	}

	var httpResponseBody []byte
	if messageBody.RequestType == "GET" {
		resp, _ := http.Get(messageBody.DestinationIp)
		httpResponseBody, _ = ioutil.ReadAll(resp.Body)
	} else if messageBody.RequestType == "POST" {
		resp, _ := http.Post(messageBody.DestinationIp, "application/json", bytes.NewBuffer(messageBody.Data))
		httpResponseBody, _ = ioutil.ReadAll(resp.Body)
	}
	// Should send message to http request here!

	dataReplyBody := &types.RelayDataResponseBody{
		UID:  messageBody.UID,
		Data: httpResponseBody,
	}

	dataReplyBodyBytes, err := json.Marshal(dataReplyBody)
	if err != nil {
		return xerrors.Errorf("Error marshaling data Response for circuit id %s\n", dataRequestMsg.CircuitId)
	}
	encryptedPayload, err := EncryptRelay(*relayCircuit, dataReplyBodyBytes)
	if err != nil {
		return xerrors.Errorf("Error encrypting data Response for circuit id %s\n", dataRequestMsg.CircuitId)
	}

	// TODO tor: send http request and attach paylod here
	dataResponse := types.RelayDataResponseMessage{
		CircuitId: dataRequestMsg.CircuitId,
		Payload:   encryptedPayload,
	}

	dataResponseMsg, err := n.conf.MessageRegistry.MarshalMessage(dataResponse)
	if err != nil {
		return xerrors.Errorf("Error marshaling data response for circuit id %s\n", dataResponse.CircuitId)
	}

	err = n.UnicastDirect(n.conf.Socket.GetAddress(), relayCircuit.firstNode.IP, dataResponseMsg)
	if err != nil {
		return xerrors.Errorf("Error sending data request for circuit id %s\n", dataResponse.CircuitId)
	}

	return nil

}

func (n *node) ExecRelayDataResponseMessage(msg types.Message, pkt transport.Packet) error {

	dataResponseMsg, ok := msg.(*types.RelayDataResponseMessage)
	if !ok {
		return xerrors.Errorf("wrong type: %T", msg)
	}

	fmt.Printf("Received Data Response Message with Circuit id %s\n", dataResponseMsg.CircuitId)

	relayCircuit := n.getRelayCircuit(dataResponseMsg.CircuitId)
	var proxyCircuit *ProxyCircuit
	if relayCircuit == nil {
		proxyCircuit = n.getProxyCircuit(dataResponseMsg.CircuitId)
	}

	if relayCircuit == nil && proxyCircuit == nil {
		fmt.Printf("Cannot find circuit %s for data response\n", dataResponseMsg.CircuitId)
		return xerrors.Errorf("Cannot find circuit %s for data response\n", dataResponseMsg.CircuitId)
	}

	if relayCircuit != nil {
		// Message received by a relay node
		// Forward it to previous circuit

		encryptedPayload, err := EncryptRelay(*relayCircuit.beforeCircuit, dataResponseMsg.Payload)
		if err != nil {
			return xerrors.Errorf("Error encrypting data Response for circuit id %s\n", dataResponseMsg.CircuitId)
		}

		// Update Circuit Id to be the next circuit id
		dataResponseMsg.CircuitId = relayCircuit.beforeCircuit.id
		dataResponseMsg.Payload = encryptedPayload
		metricsResponseMsg, err := n.conf.MessageRegistry.MarshalMessage(dataResponseMsg)
		if err != nil {
			return xerrors.Errorf("Error marshaling metric Request for circuit id %s\n", dataResponseMsg.CircuitId)
		}

		err = n.UnicastDirect(n.conf.Socket.GetAddress(), relayCircuit.beforeCircuit.firstNode.IP, metricsResponseMsg)
		if err != nil {
			return xerrors.Errorf("Error forwarding metric request for circuit id %s\n", dataResponseMsg.CircuitId)
		}

		return nil
	}

	// If this is the original proxy node then just call RTT received marking the round trip complete
	n.DataReceived(dataResponseMsg)
	return nil
}

func (n *node) DataReceived(dataResponse *types.RelayDataResponseMessage) {

	proxyCircuit := n.getProxyCircuit(dataResponse.CircuitId)

	if proxyCircuit == nil {
		fmt.Printf("cant find proxy circuit with id %s\n", dataResponse.CircuitId)
		return
	}
	decryptedPayload, err := DecryptProxy(*proxyCircuit, dataResponse.Payload)

	if err != nil {
		fmt.Printf("Error decrypting data response for proxy circuit id %s and error %s\n", dataResponse.CircuitId, err.Error())
		return
	}

	var messageBody types.RelayDataResponseBody
	err = json.Unmarshal(decryptedPayload, &messageBody)
	if err != nil {
		fmt.Printf("Error unmarshaling data response for proxy circuit id %s\n", dataResponse.CircuitId)
		return
	}

	// fmt.Printf("Response Received for request with id %s : %s\n", messageBody.UID, string(messageBody.Data))
	//TODO tor: notify sender that response has been received
	n.torDataMessagesLock.Lock()
	msg := n.messages[messageBody.UID]
	if !msg.Active {
		fmt.Printf("Message Request already timed out\n")
		return
	}

	msg.ResponseData = string(messageBody.Data)
	msg.ResponseReceived = true
	msg.ReceivedTimeStamp = time.Now()
	// fmt.Printf("Message received here and got response '%s' after %d ms\n", msg.ResponseData, msg.ReceivedTimeStamp.Sub(msg.SentTimeStamp).Milliseconds())
	n.torDataMessagesLock.Unlock()

	msg.Notify <- struct{}{}

}

func (n *node) SendMessage(httpRequestType, destinationIp, port string, data []byte) (*types.RelayHttpRequest, error) {
	dataReq := types.RelayHttpRequest{
		UID:               xid.New().String(),
		DestinationIp:     destinationIp,
		DestinationPort:   port,
		RequestType:       httpRequestType,
		Data:              data,
		Active:            true,
		ResponseData:      "",
		ResponseReceived:  false,
		SentTimeStamp:     time.Now(),
		ReceivedTimeStamp: time.Time{},
		Notify:            make(chan struct{}),
	}

	// Save message request in node
	n.torDataMessagesLock.Lock()
	n.messages[dataReq.UID] = &dataReq
	n.torDataMessagesLock.Unlock()

	//Select circuit
	c := n.SelectCircuit(&dataReq)

	if c == nil {
		return nil, errors.New("no circuit selected for this message")
	}

	dataReqBody := &types.RelayDataRequestBody{
		UID:             dataReq.UID,
		DestinationIp:   dataReq.DestinationIp,
		DestinationPort: dataReq.DestinationPort,
		RequestType:     dataReq.RequestType,
		Data:            dataReq.Data,
	}

	dataReqBodyBytes, err := json.Marshal(dataReqBody)
	fmt.Printf("Sending this message %s\n", string(dataReqBodyBytes))
	if err != nil {
		return nil, errors.New("Error marshaling data request for circuit id " + c.id)
	}

	encryptedPayload, err := EncryptProxy(*c, dataReqBodyBytes)
	if err != nil {
		return nil, errors.New("Error encrypting data request for proxy circuit id " + c.id)
	}

	dataRelayReq := &types.RelayDataRequestMessage{
		CircuitId: c.id,
		Payload:   encryptedPayload,
	}

	dataReqMsg, err := n.conf.MessageRegistry.MarshalMessage(dataRelayReq)
	if err != nil {
		return nil, errors.New("Error marshaling data request for circuit id " + dataRelayReq.CircuitId)
	}

	err = n.UnicastDirect(n.conf.Socket.GetAddress(), c.secondNode.IP, dataReqMsg)
	if err != nil {
		return nil, errors.New("Error sending data request for circuit id " + dataRelayReq.CircuitId)
	}

	// Every X minutes, each circuit gets sent a message that
	// aids in calculating the RTT
	currentRetryDuration := n.conf.DataMessageRetry

	for {
		ticker := time.NewTicker(currentRetryDuration)

		select {
		case <-ticker.C:
			currentRetryDuration *= 2
		case <-dataReq.Notify:
			// fmt.Println("Notification received for response")
			ticker.Stop()
		}

		n.torDataMessagesLock.Lock()
		received := dataReq.ResponseReceived
		n.torDataMessagesLock.Unlock()

		if received {
			// fmt.Printf("Message sent here and got response '%s' after %d ms\n", dataReq.ResponseData, dataReq.ReceivedTimeStamp.Sub(dataReq.SentTimeStamp).Milliseconds())
			n.RemoveProxyMessage(c, &dataReq)
			return &dataReq, nil
		}

		if currentRetryDuration > n.conf.DataMessageTimeout {
			n.torDataMessagesLock.Lock()
			dataReq.Active = false
			n.torDataMessagesLock.Unlock()

			n.RemoveProxyMessage(c, &dataReq)
			// TODO tor: destroy circuit
			// TODO tor: try different circuit if possible
			return nil, errors.New("request_timeout")
		}

	}
}

// End Messages/Data Relay

func (n *node) GetAllProxyCircuits(lock bool) []ProxyCircuit {
	if lock {
		n.proxiesLock.Lock()
		defer n.proxiesLock.Unlock()
	}
	cp := make([]ProxyCircuit, len(n.proxyCircuits))
	for idx, c := range n.proxyCircuits {
		cp[idx] = *c
	}
	return cp
}

func (n *node) GetAllProxyCircuitsSorted(compareTo func(circuitIdx1, circuitIdx2 int) bool, lock bool) []ProxyCircuit {
	copyCircuits := n.GetAllProxyCircuits(lock)
	sort.SliceStable(copyCircuits, compareTo)
	return copyCircuits
}

func (n *node) GetAllRelayCircuits() []RelayCircuit {
	n.relaysLock.Lock()
	defer n.relaysLock.Unlock()
	cp := make([]RelayCircuit, len(n.relayCircuits))
	for idx, c := range n.relayCircuits {
		cp[idx] = *c
	}
	return cp
}

func (n *node) GetNumberOfProxyCircuits() int {
	n.proxiesLock.Lock()
	defer n.proxiesLock.Unlock()
	return len(n.proxyCircuits)
}

func (c *ProxyCircuit) String() string {
	return fmt.Sprintf(
		"[Proxy Circuit %s] - first node %s - second node %s",
		c.id,
		c.firstNode.IP,
		c.secondNode.IP,
	)
}

func (c *RelayCircuit) String() string {
	return fmt.Sprintf(
		"[Relay Circuit %s] - first node %s - second node %s",
		c.id,
		c.firstNode.IP,
		c.secondNode.IP,
	)
}

func (n *node) StringCircuits() string {
	var s string
	for _, c := range n.GetAllProxyCircuits(false) {
		s = fmt.Sprintf("%s\n%s", s, c.String())
	}
	for _, c := range n.GetAllRelayCircuits() {
		s = fmt.Sprintf("%s\n%s", s, c.String())
	}
	return s
}

func (n *node) SendMetrics(addr string) {

	var min int64
	min = math.MaxInt64
	sum := int64(0)
	count := int64(0)

	n.torDataMessagesLock.Lock()
	defer n.torDataMessagesLock.Unlock()

	for _, msg := range n.messages {
		fmt.Printf("Message info %s, %d, %d", msg.UID, msg.SentTimeStamp.Second(), msg.ReceivedTimeStamp.Second())
		duration := msg.ReceivedTimeStamp.Sub(msg.SentTimeStamp).Microseconds()
		if duration < min {
			min = duration
		}

		sum += duration
		count += 1
	}

	average := float64(sum) / float64(count)

	postBody, _ := json.Marshal(map[string]string{
		"ip":      n.conf.Socket.GetAddress(),
		"average": fmt.Sprintf("%f", average),
		"min":     fmt.Sprintf("%d", min),
	})

	fmt.Printf("Sending metrics %s to metrics server from %s", string(postBody), n.conf.Socket.GetAddress())
	reqBody := bytes.NewBuffer(postBody)
	http.Post(addr, "application/json", reqBody)
}
