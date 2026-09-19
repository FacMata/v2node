package dispatcher

import (
	"github.com/wyx2685/v2node/common/budget"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
)

type budgetWriter struct {
	writer   buf.Writer
	account  *budget.Account
	upload   bool
	datagram bool
}

func (w *budgetWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for len(mb) > 0 {
		current := mb[0]
		mb[0] = nil
		mb = mb[1:]
		if current.IsEmpty() {
			current.Release()
			continue
		}
		pending := buf.MultiBuffer{current}
		err := w.account.Transfer(int64(current.Len()), w.upload, w.datagram, func(n int64) error {
			var prefix buf.MultiBuffer
			pending, prefix = buf.SplitSize(pending, int32(n))
			return w.writer.WriteMultiBuffer(prefix)
		})
		if err != nil {
			buf.ReleaseMulti(pending)
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return nil
}
func (w *budgetWriter) Close() error { return common.Close(w.writer) }
func (w *budgetWriter) Interrupt()   { common.Interrupt(w.writer) }

type budgetReader struct {
	reader   buf.Reader
	account  *budget.Account
	datagram bool
}

func (r *budgetReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	var accepted buf.MultiBuffer
	for len(mb) > 0 {
		current := mb[0]
		mb[0] = nil
		mb = mb[1:]
		if current.IsEmpty() {
			current.Release()
			continue
		}
		pending := buf.MultiBuffer{current}
		debitErr := r.account.Transfer(int64(current.Len()), true, r.datagram, func(n int64) error {
			var prefix buf.MultiBuffer
			pending, prefix = buf.SplitSize(pending, int32(n))
			accepted = append(accepted, prefix...)
			return nil
		})
		if debitErr != nil {
			buf.ReleaseMulti(pending)
			buf.ReleaseMulti(mb)
			return accepted, debitErr
		}
	}
	return accepted, err
}
func (r *budgetReader) Interrupt() { common.Interrupt(r.reader) }
