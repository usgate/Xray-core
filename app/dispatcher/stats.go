package dispatcher

import (
	"context"
	"sync/atomic"

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
