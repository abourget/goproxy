package goproxy
/*
	RLS 2/20/2019
	This is a simple response writer which can be used to send one shot HTTP 1.1
	responses back to a client. It's not very smart but it's not completely dumb either.
	If content-length header isn't provided, it automatically sends back a
	"Transfer-Encoding: chunked" header.

	Limitations:
	1. It is completely unaware of the calling method and should never be used to reinterpret
	responses received by downstream servers (it will mangle them). It should only ever be
	used to send back our own simple responses, such as error pages.

	2. If the caller doesn't set the content type, we'll assume text/html and utf-8.

	3. It will send everything back to the connection without buffering, whether the client
	is ready for it or not. This is generally a safe assumption for browsers, which is what
	we care about.

	Tip: It can often be useful to trace the response as it appears on the wire. To do so,
	just wrap the provided connection in a &SpyConnection{} when instantiating.
*/

import (
	"net"
	"net/http"
	//"bytes"
	"fmt"
	"strconv"
	"bufio"
)

// TODO: Implement a chunked/bufio writer so we aren't sending many small writes.
type notsodumbResponseWriter struct {
	net.Conn
	ResponseHeader		*http.Header
	wroteheaders 		bool
	chunking 		bool
	ishijacked 		bool
	//header http.Header
}

func (n *notsodumbResponseWriter) Header() http.Header {
	//fmt.Printf("[DEBUG] Header() - %+v\n", n.ResponseHeader)
	if n.ResponseHeader == nil {
		n.ResponseHeader = &http.Header{}
	}
	return *n.ResponseHeader
}

func (n *notsodumbResponseWriter) Write(buf []byte) (int, error) {
	if !n.wroteheaders {
		n.WriteHeader(200)
	}

	// Have to send the length of the chunk in hex followed by \r\n
	if !n.ishijacked && n.chunking {
		_, err := fmt.Fprintf(n.Conn, "%x\r\n", len(buf))
		if err != nil {
			fmt.Println("[DEBUG] Error writing chunk header", err)
		}
	}

	i, err := n.Conn.Write(buf)
	if !n.ishijacked && n.chunking {
		n.Conn.Write([]byte("\r\n"))
	}
	return i, err
}

// Writes the headers back to the wire.
func (n *notsodumbResponseWriter) WriteHeader(code int) {

	// Don't write headers if hijacked. Don't write headers twice.
	if n.ishijacked || n.wroteheaders {
		return
	}

	n.wroteheaders = true
	header := "HTTP/1.1 " + strconv.Itoa(code) + " " + http.StatusText(code) + "\r\n"
	//fmt.Println("[DEBUG] WriteHeader() - Writing Headers", header, n.ishijacked)


	// If content length wasn't provided, then add a transfer-encoding header
	if n.Header().Get("content-length") == "" {
		n.ResponseHeader.Set("transfer-encoding", "chunked")
		n.chunking = true
	}

	// LinkedIn doesn't send content-type headers. Don't be like LinkedIn.
	if n.ResponseHeader.Get("Content-Type") == "" {
		n.ResponseHeader.Set("Content-Type", "text/html; charset=utf-8")
	}

	n.Conn.Write([]byte(header))

	if n.ResponseHeader != nil {
		n.ResponseHeader.Write(n.Conn)
	}
	n.Conn.Write([]byte("\r\n"))
}

// Implements the Flush interface so the response is completed.
func (n *notsodumbResponseWriter) Flush() {
	if n.ishijacked {
		return
	}
	if !n.wroteheaders {
		n.WriteHeader(200)
	}

	if n.chunking {
		// zero chunk to mark EOF
		n.Conn.Write([]byte("0\r\n"))
	}

	n.Conn.Write([]byte("\r\n"))


}

func (n *notsodumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	n.ishijacked = true
	return n, bufio.NewReadWriter(bufio.NewReader(n), bufio.NewWriter(n)), nil
}
