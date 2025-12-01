package dispatcher

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/stats"
)

type SizeStatWriter struct {
	Counter stats.Counter
	Writer  buf.Writer
}

func (w *SizeStatWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.Counter.Add(int64(mb.Len()))
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *SizeStatWriter) Close() error {
	return common.Close(w.Writer)
}

func (w *SizeStatWriter) Interrupt() {
	common.Interrupt(w.Writer)
}

// TrafficLogWriter wraps a Writer to track downlink traffic for logging
type TrafficLogWriter struct {
	Writer        buf.Writer
	ctx           context.Context
	domain        string
	outboundTag   string
	isRouted      bool
	downlinkBytes *int64
	uplinkBytes   *int64
	logged        *int32
}

func (w *TrafficLogWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	size := int64(mb.Len())
	atomic.AddInt64(w.downlinkBytes, size)
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *TrafficLogWriter) Close() error {
	w.logTraffic()
	return common.Close(w.Writer)
}

func (w *TrafficLogWriter) Interrupt() {
	w.logTraffic()
	common.Interrupt(w.Writer)
}

func (w *TrafficLogWriter) logTraffic() {
	if atomic.CompareAndSwapInt32(w.logged, 0, 1) {
		uplink := atomic.LoadInt64(w.uplinkBytes)
		downlink := atomic.LoadInt64(w.downlinkBytes)
		routed := "no"
		if w.isRouted {
			routed = "yes"
		}
		// 总是输出日志，即使流量为 0（可能是连接失败或刚建立就关闭）
		errors.LogInfo(w.ctx, "[Traffic] Domain: ", w.domain, ", Routed: ", routed,
			", Outbound: ", w.outboundTag, ", Uplink: ", uplink, " bytes, Downlink: ", downlink, " bytes")
	}
}

// TrafficLogReader wraps a Reader to track uplink traffic for logging
type TrafficLogReader struct {
	Reader      buf.Reader
	uplinkBytes *int64
}

func (r *TrafficLogReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	if !mb.IsEmpty() {
		size := int64(mb.Len())
		atomic.AddInt64(r.uplinkBytes, size)
	}
	return mb, err
}

func (r *TrafficLogReader) ReadMultiBufferTimeout(duration time.Duration) (buf.MultiBuffer, error) {
	// 如果底层 Reader 支持超时读取，使用它
	if tr, ok := r.Reader.(buf.TimeoutReader); ok {
		mb, err := tr.ReadMultiBufferTimeout(duration)
		if !mb.IsEmpty() {
			size := int64(mb.Len())
			atomic.AddInt64(r.uplinkBytes, size)
		}
		return mb, err
	}
	// 否则降级为普通读取
	return r.ReadMultiBuffer()
}
