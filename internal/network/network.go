// Package network provides the transports that move encoded envelopes
// between nodes:
//
//   - MemNetwork : an in-process network for simulations and tests. It models
//     latency + jitter, keeps every link FIFO (like a TCP connection), counts
//     bytes, and lets the experiment inject faults (crash a node, intercept /
//     tamper / replay frames as a network adversary would).
//   - TCPTransport (tcp.go) : real sockets for the multi-process / Docker
//     deployment.
package network

import (
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// Packet is one received frame.
type Packet struct {
	From uint32
	Data []byte
}

// Transport is what a node needs from the network.
type Transport interface {
	Send(to uint32, data []byte) error
	Inbox() <-chan Packet
	Close() error
}

// Interceptor lets a test or experiment act as the network adversary.
// It may return modified bytes, drop the frame (deliver=false), or inject
// extra frames through the network's Inject method.
type Interceptor func(from, to uint32, data []byte) (out []byte, deliver bool)

// LinkConfig describes the simulated links.
type LinkConfig struct {
	BaseLatency time.Duration
	Jitter      time.Duration // uniform extra delay in [0, Jitter)
	DropRate    float64       // probability that a frame is lost
}

// MemNetwork is an in-memory network shared by all nodes of a simulation.
type MemNetwork struct {
	cfg LinkConfig

	mu          sync.Mutex
	endpoints   map[uint32]*memEndpoint
	links       map[[2]uint32]*link
	down        map[uint32]bool
	interceptor Interceptor

	BytesSent  []atomic.Uint64 // per node
	FramesSent []atomic.Uint64
}

type link struct {
	mu       sync.Mutex
	lastDue  time.Time
	queue    chan delivery
}

type delivery struct {
	due  time.Time
	pkt  Packet
	to   uint32
}

// NewMemNetwork builds a network for n nodes (ids 0..n-1).
func NewMemNetwork(n int, cfg LinkConfig) *MemNetwork {
	return &MemNetwork{
		cfg:        cfg,
		endpoints:  map[uint32]*memEndpoint{},
		links:      map[[2]uint32]*link{},
		down:       map[uint32]bool{},
		BytesSent:  make([]atomic.Uint64, n),
		FramesSent: make([]atomic.Uint64, n),
	}
}

// SetInterceptor installs (or removes, with nil) a network adversary.
func (n *MemNetwork) SetInterceptor(i Interceptor) {
	n.mu.Lock()
	n.interceptor = i
	n.mu.Unlock()
}

// SetDown crashes (true) or revives (false) a node: frames to and from it vanish.
func (n *MemNetwork) SetDown(id uint32, down bool) {
	n.mu.Lock()
	n.down[id] = down
	n.mu.Unlock()
}

// Endpoint returns the transport of node id.
func (n *MemNetwork) Endpoint(id uint32) Transport {
	n.mu.Lock()
	defer n.mu.Unlock()
	ep := &memEndpoint{net: n, id: id, inbox: make(chan Packet, 4096), done: make(chan struct{})}
	n.endpoints[id] = ep
	return ep
}

// Inject delivers raw bytes as if they came from `from` (replay attacks).
func (n *MemNetwork) Inject(from, to uint32, data []byte) {
	n.enqueue(from, to, append([]byte(nil), data...))
}

func (n *MemNetwork) getLink(from, to uint32) *link {
	key := [2]uint32{from, to}
	n.mu.Lock()
	defer n.mu.Unlock()
	l := n.links[key]
	if l == nil {
		l = &link{queue: make(chan delivery, 4096)}
		n.links[key] = l
		go n.pump(l)
	}
	return l
}

// pump delivers the frames of one link in order, each at its due time.
func (n *MemNetwork) pump(l *link) {
	for d := range l.queue {
		if wait := time.Until(d.due); wait > 0 {
			time.Sleep(wait)
		}
		n.mu.Lock()
		ep := n.endpoints[d.to]
		dead := n.down[d.to]
		n.mu.Unlock()
		if ep == nil || dead {
			continue
		}
		select {
		case ep.inbox <- d.pkt:
		case <-ep.done: // receiver stopped: drop instead of blocking the link
		}
	}
}

func (n *MemNetwork) enqueue(from, to uint32, data []byte) {
	l := n.getLink(from, to)
	delay := n.cfg.BaseLatency
	if n.cfg.Jitter > 0 {
		delay += time.Duration(rand.Int64N(int64(n.cfg.Jitter)))
	}
	l.mu.Lock()
	due := time.Now().Add(delay)
	if due.Before(l.lastDue) { // FIFO: never overtake an earlier frame
		due = l.lastDue
	}
	l.lastDue = due
	l.mu.Unlock()
	select {
	case l.queue <- delivery{due: due, to: to, pkt: Packet{From: from, Data: data}}:
	default: // link overloaded: lose the frame (never block the sender's event loop)
	}
}

type memEndpoint struct {
	net   *MemNetwork
	id    uint32
	inbox chan Packet
	done  chan struct{}
	once  sync.Once
}

func (e *memEndpoint) Send(to uint32, data []byte) error {
	n := e.net
	n.mu.Lock()
	dead := n.down[e.id]
	icpt := n.interceptor
	n.mu.Unlock()
	if dead {
		return nil
	}
	if int(e.id) < len(n.BytesSent) {
		n.BytesSent[e.id].Add(uint64(len(data)))
		n.FramesSent[e.id].Add(1)
	}
	if n.cfg.DropRate > 0 && rand.Float64() < n.cfg.DropRate {
		return nil
	}
	buf := append([]byte(nil), data...)
	if icpt != nil {
		var deliver bool
		if buf, deliver = icpt(e.id, to, buf); !deliver {
			return nil
		}
	}
	n.enqueue(e.id, to, buf)
	return nil
}

func (e *memEndpoint) Inbox() <-chan Packet { return e.inbox }

func (e *memEndpoint) Close() error {
	e.once.Do(func() { close(e.done) })
	return nil
}
