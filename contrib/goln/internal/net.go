package internal

import (
	"io"
	"net"
	"sync"
	"time"
)

type ReadWriterConn struct {
	in  io.ReadCloser
	out io.WriteCloser
}

// Close implements net.Conn
func (conn *ReadWriterConn) Close() error {
	err := conn.in.Close()
	if err != nil {
		return err
	}
	return conn.out.Close()
}

// LocalAddr implements net.Conn
func (conn *ReadWriterConn) LocalAddr() net.Addr {
	return nil
}

// Read implements net.Conn
func (conn *ReadWriterConn) Read(b []byte) (n int, err error) {
	return conn.in.Read(b)
}

// RemoteAddr implements net.Conn
func (conn *ReadWriterConn) RemoteAddr() net.Addr {
	return nil
}

// SetDeadline implements net.Conn
func (conn *ReadWriterConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline implements net.Conn
func (conn *ReadWriterConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline implements net.Conn
func (conn *ReadWriterConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// Write implements net.Conn
func (conn *ReadWriterConn) Write(b []byte) (n int, err error) {
	return conn.out.Write(b)
}

func NewReadWriterConn(in io.ReadCloser, out io.WriteCloser) net.Conn {
	return &ReadWriterConn{in: in, out: out}
}

type ReadWriteListener struct {
	connectionOnce sync.Once
	closeOnce      sync.Once
	connChan       chan net.Conn

	in  io.ReadCloser
	out io.WriteCloser
}

func NewReadWriteListener(in io.ReadCloser, out io.WriteCloser) net.Listener {
	lis := new(ReadWriteListener)
	lis.in = in
	lis.out = out
	lis.connChan = make(chan net.Conn, 1)
	return lis
}

// Accept implements net.Listener
func (listener *ReadWriteListener) Accept() (net.Conn, error) {
	listener.connectionOnce.Do(func() {
		conn := NewReadWriterConn(listener.in, listener.out)
		listener.connChan <- conn
	})
	conn := <-listener.connChan
	return conn, nil
}

// Addr implements net.Listener
func (listener *ReadWriteListener) Addr() net.Addr {
	return nil
}

// Close implements net.Listener
func (listener *ReadWriteListener) Close() error {
	listener.closeOnce.Do(func() {
		listener.in.Close()
		listener.out.Close()
		close(listener.connChan)
	})
	return nil
}
