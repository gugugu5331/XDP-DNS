// Package xdp 提供多队列 AF_XDP Socket 管理
package xdp

import (
	"context"
	"fmt"
	"log"
	"sync"
)

// QueueManager 管理多个 RX 队列的 AF_XDP Sockets
type QueueManager struct {
	ifindex    int
	program    *Program
	sockets    []*Socket
	queueStart int
	queueCount int
	opts       *SocketOptions

	mu     sync.RWMutex
	closed bool
}

// QueueManagerConfig 队列管理器配置
type QueueManagerConfig struct {
	Ifindex    int            // 网卡索引
	QueueStart int            // 起始队列 ID
	QueueCount int            // 队列数量
	SocketOpts *SocketOptions // Socket 配置
}

// NewQueueManager 创建多队列管理器
func NewQueueManager(cfg QueueManagerConfig, program *Program) (*QueueManager, error) {
	if cfg.QueueCount <= 0 {
		cfg.QueueCount = 1
	}
	if cfg.SocketOpts == nil {
		cfg.SocketOpts = &DefaultSocketOptions
	}

	qm := &QueueManager{
		ifindex:    cfg.Ifindex,
		program:    program,
		queueStart: cfg.QueueStart,
		queueCount: cfg.QueueCount,
		opts:       cfg.SocketOpts,
		sockets:    make([]*Socket, cfg.QueueCount),
	}

	// 为每个队列创建 Socket
	for i := 0; i < cfg.QueueCount; i++ {
		queueID := cfg.QueueStart + i
		socket, err := NewSocket(cfg.Ifindex, queueID, cfg.SocketOpts)
		if err != nil {
			// 清理已创建的 sockets
			qm.Close()
			return nil, fmt.Errorf("failed to create socket for queue %d: %w", queueID, err)
		}
		qm.sockets[i] = socket

		// 注册到 XDP 程序
		if err := program.Register(queueID, socket.FD()); err != nil {
			qm.Close()
			return nil, fmt.Errorf("failed to register socket for queue %d: %w", queueID, err)
		}
		log.Printf("Queue %d: socket created and registered (fd=%d)", queueID, socket.FD())
	}

	return qm, nil
}

// GetSocket 获取指定队列的 Socket
func (qm *QueueManager) GetSocket(queueID int) *Socket {
	qm.mu.RLock()
	defer qm.mu.RUnlock()

	idx := queueID - qm.queueStart
	if idx < 0 || idx >= len(qm.sockets) {
		return nil
	}
	return qm.sockets[idx]
}

// GetSockets 获取所有 Sockets
func (qm *QueueManager) GetSockets() []*Socket {
	qm.mu.RLock()
	defer qm.mu.RUnlock()
	return qm.sockets
}

// QueueCount 返回队列数量
func (qm *QueueManager) QueueCount() int {
	return qm.queueCount
}

// QueueStart 返回起始队列 ID
func (qm *QueueManager) QueueStart() int {
	return qm.queueStart
}

// Close 关闭所有 Sockets
func (qm *QueueManager) Close() error {
	qm.mu.Lock()
	defer qm.mu.Unlock()

	if qm.closed {
		return nil
	}
	qm.closed = true

	var firstErr error
	for i, socket := range qm.sockets {
		if socket != nil {
			queueID := qm.queueStart + i
			// 取消注册
			if qm.program != nil {
				qm.program.Unregister(queueID)
			}
			// 关闭 socket
			if err := socket.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
			qm.sockets[i] = nil
		}
	}
	return firstErr
}

// ReceivedPacket 表示从队列接收到的数据包
type ReceivedPacket struct {
	QueueID int    // 来源队列 ID
	Desc    Desc   // XDP 描述符
	Data    []byte // 数据包内容 (指向 UMEM)
	Socket  *Socket // 所属的 Socket (用于发送响应)
}

// StartReceiver 启动接收器，从所有队列接收数据包
// 返回一个 channel 用于接收数据包
func (qm *QueueManager) StartReceiver(ctx context.Context, batchSize int) <-chan ReceivedPacket {
	if batchSize <= 0 {
		batchSize = 64
	}

	packets := make(chan ReceivedPacket, qm.queueCount*1024)

	// 为每个队列启动一个接收协程
	for i := 0; i < qm.queueCount; i++ {
		queueID := qm.queueStart + i
		socket := qm.sockets[i]
		go qm.receiveLoop(ctx, queueID, socket, packets, batchSize)
	}

	return packets
}

// receiveLoop 单个队列的接收循环
func (qm *QueueManager) receiveLoop(ctx context.Context, queueID int, socket *Socket, out chan<- ReceivedPacket, batchSize int) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 填充 Fill Ring
		descs := socket.GetDescs(socket.NumFreeFillSlots(), true)
		if len(descs) > 0 {
			socket.Fill(descs)
		}

		// 轮询
		numRx, _, err := socket.Poll(100) // 100ms 超时
		if err != nil {
			log.Printf("Queue %d poll error: %v", queueID, err)
			continue
		}

		if numRx == 0 {
			continue
		}

		// 接收数据包
		rxDescs := socket.Receive(numRx)
		for _, desc := range rxDescs {
			pkt := ReceivedPacket{
				QueueID: queueID,
				Desc:    desc,
				Data:    socket.GetFrame(desc),
				Socket:  socket,
			}

			select {
			case out <- pkt:
			case <-ctx.Done():
				return
			default:
				// 队列满，丢弃
				log.Printf("Queue %d: packet dropped (channel full)", queueID)
			}
		}
	}
}

