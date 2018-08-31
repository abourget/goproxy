// RLS 8/31/2018
// A responsewriter that will pass headers back to the underlying connection. Based on dumbresponsewriter.
package goproxy

import (
	"net"
	"net/http"
	"bytes"
	//"fmt"
)

type notsodumbResponseWriter struct {
	net.Conn
	ResponseHeader		*http.Header
	//header http.Header
}

func (n notsodumbResponseWriter) Header() http.Header {
	//fmt.Printf("[DEBUG] Header() - %+v\n", n.ResponseHeader)
	if n.ResponseHeader == nil {
		//fmt.Printf("[DEBUG] Header() - creating new header\n")

		n.ResponseHeader = &http.Header{}
	}
	return *n.ResponseHeader
}

func (n notsodumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		// throw away the HTTP OK response from the faux CONNECT request
		return len(buf), nil
	}
	return n.Conn.Write(buf)
}

func (n notsodumbResponseWriter) WriteHeader(code int) {
	if n.ResponseHeader != nil {
		n.ResponseHeader.Write(n.Conn)
	}
	n.Conn.Write([]byte("\r\n"))
}

