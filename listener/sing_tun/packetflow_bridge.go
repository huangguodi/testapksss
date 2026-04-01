package sing_tun

import (
	"errors"
	"sync"
	"github.com/metacubex/mihomo/log"
)

type PacketFlowPacket struct {
	data []byte
	af   int64
}

func NewPacketFlowPacket(data []byte, af int64) *PacketFlowPacket {
	bPtr := packetDataPool.Get().(*[]byte)
	b := *bPtr
	if cap(b) < len(data) {
		b = make([]byte, len(data))
	} else {
		b = b[:len(data)]
	}
	copy(b, data)
	return &PacketFlowPacket{data: b, af: af}
}

func (p *PacketFlowPacket) Data() []byte {
	if p == nil {
		return nil
	}
	return append([]byte(nil), p.data...)
}

func (p *PacketFlowPacket) AF() int64 {
	if p == nil {
		return 0
	}
	return p.af
}

type PacketFlowBridge interface {
	ReadPacket() *PacketFlowPacket
	WritePacket(packet *PacketFlowPacket) bool
	OnPacketFlowError(message string)
}

var (
	packetFlowBridgeMu sync.RWMutex
	packetFlowBridge   PacketFlowBridge
	packetInboundQueue chan *PacketFlowPacket

	// Memory pool for raw packet data to reduce GC spikes (Optimization Point 2)
	packetDataPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, 1500) // MTU size
			return &b
		},
	}
)

func SetPacketFlowBridge(bridge PacketFlowBridge) {
	packetFlowBridgeMu.Lock()
	packetFlowBridge = bridge
	if bridge != nil && packetInboundQueue == nil {
		// 降低队列长度到 1024，避免因队列堆积导致内存溢出 (1024 * 1500B ≈ 1.5MB)
		packetInboundQueue = make(chan *PacketFlowPacket, 1024)
	}
	if bridge == nil {
		packetInboundQueue = nil
	}
	packetFlowBridgeMu.Unlock()
}

func ClearPacketFlowBridge() {
	SetPacketFlowBridge(nil)
}

func getPacketFlowBridge() PacketFlowBridge {
	packetFlowBridgeMu.RLock()
	bridge := packetFlowBridge
	packetFlowBridgeMu.RUnlock()
	return bridge
}

func FeedPacketBytes(data []byte, af int64) bool {
	if len(data) == 0 {
		return false
	}
	packetFlowBridgeMu.RLock()
	queue := packetInboundQueue
	packetFlowBridgeMu.RUnlock()
	if queue == nil {
		return false
	}
	
	// Use pool to avoid allocation
	bPtr := packetDataPool.Get().(*[]byte)
	b := *bPtr
	if cap(b) < len(data) {
		b = make([]byte, len(data))
	} else {
		b = b[:len(data)]
	}
	copy(b, data)
	
	packet := &PacketFlowPacket{data: b, af: af}
	select {
	case queue <- packet:
		return true
	default:
		// Queue full, return memory to pool
		packetDataPool.Put(&b)
		return false
	}
}

func FeedPacketFromFlow(packet *PacketFlowPacket) bool {
	if packet == nil || len(packet.data) == 0 {
		return false
	}
	packetFlowBridgeMu.RLock()
	queue := packetInboundQueue
	packetFlowBridgeMu.RUnlock()
	if queue == nil {
		return false
	}
	select {
	case queue <- NewPacketFlowPacket(packet.data, packet.af):
		return true
	default:
		return false
	}
}

type packetFlowTun struct {
	bridge PacketFlowBridge
	closed chan struct{}
	queue  chan *PacketFlowPacket
}

func newPacketFlowTun(bridge PacketFlowBridge) *packetFlowTun {
	packetFlowBridgeMu.RLock()
	queue := packetInboundQueue
	packetFlowBridgeMu.RUnlock()
	return &packetFlowTun{
		bridge: bridge,
		closed: make(chan struct{}),
		queue:  queue,
	}
}

func (t *packetFlowTun) Read(p []byte) (int, error) {
	if t.queue == nil {
		return 0, errors.New("packet queue not initialized")
	}
	for {
		select {
		case <-t.closed:
			return 0, errors.New("closed")
		case packet := <-t.queue:
			if packet == nil || len(packet.data) == 0 {
				continue
			}
			payloadLen := len(packet.data)
			if payloadLen > len(p) {
				payloadLen = len(p)
			}
			if payloadLen == 0 {
				return 0, nil
			}
			copy(p[:payloadLen], packet.data[:payloadLen])
			
			// Return to pool after reading
			if cap(packet.data) >= 1500 {
				reusableSlice := packet.data[:cap(packet.data)]
				packetDataPool.Put(&reusableSlice)
			}
			
			return payloadLen, nil
		}
	}
}

func (t *packetFlowTun) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return len(p), nil
	}
	var af int64
	version := p[0] >> 4
	if version == 4 {
		af = 2 // AF_INET on Darwin
	} else if version == 6 {
		af = 30 // AF_INET6 on Darwin
	} else {
		return len(p), nil
	}
	packet := NewPacketFlowPacket(p, af)
	if !t.bridge.WritePacket(packet) {
		t.bridge.OnPacketFlowError("write packet failed")
	}
	
	// WritePacket (通过 gomobile 到 Swift) 是同步拷贝过程
	// 返回后可以安全地将内存放回内存池，避免持续产生 GC 压力
	if cap(packet.data) >= 1500 {
		reusableSlice := packet.data[:cap(packet.data)]
		packetDataPool.Put(&reusableSlice)
	}
	
	return len(p), nil
}

func (t *packetFlowTun) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}
