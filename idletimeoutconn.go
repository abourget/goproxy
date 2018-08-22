package goproxy

import (
	"net"
	"time"
)

const serverIdleTimeout = 60 	// idle timeout in seconds

// Wraps net.conn to enforce idle connection timeout during io.Copy().
type IdleTimeoutConn struct {
	Conn net.Conn
}

func (idleconn *IdleTimeoutConn) Read(buf []byte) (int, error) {
	idleconn.Conn.SetDeadline(time.Now().Add(serverIdleTimeout * time.Second))
	return idleconn.Conn.Read(buf)
}

func (idleconn *IdleTimeoutConn) Write(buf []byte) (int, error) {
	idleconn.Conn.SetDeadline(time.Now().Add(serverIdleTimeout * time.Second))
	return idleconn.Conn.Write(buf)
}

func (idleconn *IdleTimeoutConn) Close() (error) {
	return idleconn.Conn.Close()
}

func (idleconn *IdleTimeoutConn) LocalAddr() net.Addr {
	return idleconn.Conn.LocalAddr()
}

func (idleconn *IdleTimeoutConn) RemoteAddr() net.Addr {
	return idleconn.Conn.RemoteAddr()
}

func (idleconn *IdleTimeoutConn) SetDeadline(t time.Time) error {
	return idleconn.Conn.SetDeadline(t)
}

func (idleconn *IdleTimeoutConn) SetReadDeadline(t time.Time) error {
	return idleconn.Conn.SetReadDeadline(t)
}

func (idleconn *IdleTimeoutConn) SetWriteDeadline(t time.Time) error {
	return idleconn.Conn.SetWriteDeadline(t)
}