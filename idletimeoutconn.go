package goproxy

import (
	"net"
	"time"
)

//const serverIdleTimeout = 60 	// idle timeout in seconds

// Wraps net.conn to enforce idle connection timeout during io.Copy().
type IdleTimeoutConn struct {
	Conn net.Conn
	IdleTimeout 	int
	Deadline 	time.Time
}

// Update the connection timeout. Call immediately before reading or writing.
func (idleconn *IdleTimeoutConn) settimeout() {
	// Default idle timeout
	timeout := time.Now().Add(time.Duration(connectionIdleTimeout) * time.Second)

	// Custom idle timeout
	if idleconn.IdleTimeout > 0 {
		timeout = time.Now().Add(time.Duration(idleconn.IdleTimeout) * time.Second)
	}

	// Global deadline - occurs before idle timeout
	if !idleconn.Deadline.IsZero() && idleconn.Deadline.Before(timeout) {
		timeout = idleconn.Deadline
	}
	idleconn.Conn.SetDeadline(timeout)
}

func (idleconn *IdleTimeoutConn) Read(buf []byte) (int, error) {
	idleconn.settimeout()
	return idleconn.Conn.Read(buf)
}

func (idleconn *IdleTimeoutConn) Write(buf []byte) (int, error) {
	idleconn.settimeout()
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
	idleconn.Deadline = t
	return idleconn.Conn.SetDeadline(t)
}

func (idleconn *IdleTimeoutConn) SetReadDeadline(t time.Time) error {
	idleconn.Deadline = t
	return idleconn.Conn.SetReadDeadline(t)
}

func (idleconn *IdleTimeoutConn) SetWriteDeadline(t time.Time) error {
	idleconn.Deadline = t
	return idleconn.Conn.SetWriteDeadline(t)
}