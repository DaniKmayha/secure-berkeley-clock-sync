package network

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// TCPTransport is the transport used by the real multi-process deployment
// (cmd/node, Docker Compose). Frames are length-prefixed:
//
//	uint32 length | uint32 sender id | payload
//
// TCP gives the per-link FIFO ordering the session layer relies on.
// The sender id in the frame is only a routing hint: authenticity comes from
// the session layer (AEAD / transcript signatures), never from the socket.
type TCPTransport struct {
	self  uint32
	addrs map[uint32]string

	mu    sync.Mutex
	conns map[uint32]net.Conn

	ln     net.Listener
	inbox  chan Packet
	closed atomic.Bool

	BytesSent atomic.Uint64
}

const maxFrame = 4 << 20 // 4 MiB, bounds memory used by a malicious peer

// NewTCPTransport listens on listenAddr; addrs maps node id -> host:port.
func NewTCPTransport(self uint32, listenAddr string, addrs map[uint32]string) (*TCPTransport, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	t := &TCPTransport{self: self, addrs: addrs, conns: map[uint32]net.Conn{}, ln: ln, inbox: make(chan Packet, 4096)}
	go t.acceptLoop()
	return t, nil
}

func (t *TCPTransport) acceptLoop() {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			if t.closed.Load() {
				return
			}
			continue
		}
		go t.readLoop(c)
	}
}

func (t *TCPTransport) readLoop(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(hdr[0:4])
		from := binary.BigEndian.Uint32(hdr[4:8])
		if n > maxFrame {
			return
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return
		}
		select {
		case t.inbox <- Packet{From: from, Data: buf}:
		default: // inbox full: drop (the protocols tolerate loss via timeouts)
		}
	}
}

func (t *TCPTransport) dial(to uint32) (net.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c := t.conns[to]; c != nil {
		return c, nil
	}
	addr, ok := t.addrs[to]
	if !ok {
		return nil, fmt.Errorf("tcp: no address for node %d", to)
	}
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	t.conns[to] = c
	return c, nil
}

// Send writes one frame to node `to` (dialing on first use, redialing once on error).
func (t *TCPTransport) Send(to uint32, data []byte) error {
	if t.closed.Load() {
		return errors.New("tcp: closed")
	}
	frame := make([]byte, 8+len(data))
	binary.BigEndian.PutUint32(frame[0:4], uint32(len(data)))
	binary.BigEndian.PutUint32(frame[4:8], t.self)
	copy(frame[8:], data)
	for attempt := 0; attempt < 2; attempt++ {
		c, err := t.dial(to)
		if err != nil {
			return err
		}
		_ = c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err = c.Write(frame); err == nil {
			t.BytesSent.Add(uint64(len(frame)))
			return nil
		}
		t.mu.Lock()
		c.Close()
		delete(t.conns, to)
		t.mu.Unlock()
	}
	return fmt.Errorf("tcp: send to %d failed", to)
}

func (t *TCPTransport) Inbox() <-chan Packet { return t.inbox }

func (t *TCPTransport) Close() error {
	t.closed.Store(true)
	t.mu.Lock()
	for _, c := range t.conns {
		c.Close()
	}
	t.mu.Unlock()
	return t.ln.Close()
}
