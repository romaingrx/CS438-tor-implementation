package udp

import (
	"math"
	"net"
	"sync"
	"time"

	"go.dedis.ch/cs438/internal/traffic"

	"go.dedis.ch/cs438/transport"
)

const bufSize = 65000

// NewUDP returns a new udp transport implementation.
func NewUDP() transport.Transport {
	return &UDP{
		traffic: traffic.NewTraffic(),
	}
}

// UDP implements a transport layer using UDP
//
// - implements transport.Transport
type UDP struct {
	traffic *traffic.Traffic
}

// CreateSocket implements transport.Transport
func (n *UDP) CreateSocket(address string) (transport.ClosableSocket, error) {

	// Resolve the address to confirm the correctness of it and cast it as a *net.UDPAddr pointer
	// Assign a random open port if the port is set to 0
	udpAddress, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return nil, err
	}

	// Set the connection socket
	// Throw an error if the port is already bound
	connection, err := net.ListenUDP("udp4", udpAddress)
	if err != nil {
		return nil, err
	}

	return &Socket{
		UDP:        n,
		connection: connection,

		ins:  packets{},
		outs: packets{},
	}, nil
}

// Socket implements a network socket using UDP.
//
// - implements transport.Socket
// - implements transport.ClosableSocket
type Socket struct {
	*UDP
	connection *net.UDPConn

	ins  packets
	outs packets
}

// Close implements transport.Socket. It returns an error if already closed.
func (s *Socket) Close() error {
	// Throw an exception if already closed
	return s.connection.Close()
}

// Send implements transport.Socket
func (s *Socket) Send(dest string, pkt transport.Packet, timeout time.Duration) error {

	// Timeout set to the max int value on 64 bits if previously set to 0
	if timeout == 0 {
		timeout = math.MaxInt64 * time.Nanosecond
	}

	// Resolve the address to confirm the correctness of it and cast it as a *net.UDPAddr pointer
	destUDPAddr, err := net.ResolveUDPAddr("udp4", dest)
	if err != nil {
		return err
	}

	// Cast the packet as byte array in order to send it over the network
	pktMarshaled, err := pkt.Marshal()
	if err != nil {
		return err
	}

	// Set a deadline for the sending of a packet
	err = s.connection.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		return err
	}

	// Send the packet over the UDP connection
	_, err = s.connection.WriteToUDP(pktMarshaled, destUDPAddr)
	if err != nil {
		return err
	}

	// Add the sent packet in the outs packets (threadsafe)
	s.outs.add(pkt)
	s.traffic.LogSent(pkt.Header.RelayedBy, dest, pkt)

	return nil
}

// Recv implements transport.Socket. It blocks until a packet is received, or
// the timeout is reached. In the case the timeout is reached, return a
// TimeoutErr.
func (s *Socket) Recv(timeout time.Duration) (transport.Packet, error) {

	buffer := make([]byte, bufSize) // Create the buffer in order to receive the packet

	// Timeout set to 1 second if previously set to 0
	if timeout == 0 {
		timeout = time.Second
	}

	// Set the deadline for which the connection will wait in order to read received bytes from UDP
	err := s.connection.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return transport.Packet{}, err
	}

	// Read the bytes received on the UDP connection
	bytesReceived, _, err := s.connection.ReadFromUDP(buffer)
	if err != nil {
		e, _ := err.(net.Error)
		if e.Timeout() {
			return transport.Packet{}, transport.TimeoutErr(timeout)
		}
		return transport.Packet{}, err
	}

	// Cast the received message as a packet
	pkt := transport.Packet{}
	err = pkt.Unmarshal(buffer[:bytesReceived])
	if err != nil {
		return transport.Packet{}, err
	}

	// Add the sent packet in the ins packets (threadsafe)
	s.traffic.LogRecv(pkt.Header.RelayedBy, s.GetAddress(), pkt)
	s.ins.add(pkt)

	return pkt, nil
}

// GetAddress implements transport.Socket. It returns the address assigned. Can
// be useful in the case one provided a :0 address, which makes the system use a
// random free port.
func (s *Socket) GetAddress() string {
	return s.connection.LocalAddr().String()
}

// GetIns implements transport.Socket
func (s *Socket) GetIns() []transport.Packet {
	return s.ins.getAll()
}

// GetOuts implements transport.Socket
func (s *Socket) GetOuts() []transport.Packet {
	return s.outs.getAll()
}

type packets struct {
	sync.Mutex
	data []transport.Packet
}

func (p *packets) add(pkt transport.Packet) {
	p.Lock()
	defer p.Unlock()

	p.data = append(p.data, pkt)
}

func (p *packets) getAll() []transport.Packet {
	p.Lock()
	defer p.Unlock()

	// Create a transport.Packet list with the same length as p.data
	res := make([]transport.Packet, len(p.data))

	// Copy each packet in the new list
	for i, pkt := range p.data {
		res[i] = pkt.Copy()
	}

	return res
}
