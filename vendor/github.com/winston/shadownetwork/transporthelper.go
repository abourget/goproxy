// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// RLS 7/16/2018: This file contains additional functions cloned from the standard
// http package which are required by transport.go.

package shadownetwork

import (
	httplex "golang.org/x/net/http/httpguts"
	"unicode/utf8"
	"golang.org/x/net/idna"
	"fmt"
	"net/http"
	"github.com/pkg/errors"
	"strings"
	"io"
	"bufio"
	"net"
)


type readResult struct {
	n   int
	err error
	b   byte // byte read, if n == 1
}

// requestBodyReadError wraps an error from (*Request).write to indicate
// that the error came from a Read call on the Request.Body.
// This error type should not escape the net/http package to users.
type requestBodyReadError struct{ error }

var errMissingHost = errors.New("http: Request.Write on Request with no Host or URL set")

// Headers that Request.Write handles itself and should be skipped.
var reqWriteExcludeHeader = map[string]bool{
	"Host":              true, // not in Header map anyway
	"User-Agent":        true,
	"Content-Length":    true,
	"Transfer-Encoding": true,
	"Trailer":           true,
}

// maxInt64 is the effective "infinite" value for the Server and
// Transport's byte-limiting readers.
const maxInt64 = 1<<63 - 1

func closeBody(req *http.Request) {
	if req.Body != nil {
		req.Body.Close()
	}
}

type badStringError struct {
	what string
	str  string
}


func (e *badStringError) Error() string { return fmt.Sprintf("%s %q", e.what, e.str) }

func validMethod(method string) bool {
	return len(method) > 0 && strings.IndexFunc(method, isNotToken) == -1
}

func isNotToken(r rune) bool {
	return !httplex.IsTokenRune(r)
}

// outgoingLength reports the Content-Length of this outgoing (Client) request.
// It maps 0 into -1 (unknown) when the Body is non-nil.
func outgoingLength(r *http.Request) int64 {
	if r.Body == nil || r.Body == http.NoBody {
		return 0
	}

	if r.ContentLength != 0 {
		return r.ContentLength
	}

	return -1
}

func isReplayable(r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody || r.GetBody != nil {
		switch valueOrDefault(r.Method, "GET") {
		case "GET", "HEAD", "OPTIONS", "TRACE":
			return true
		}
	}
	return false
}

// Return value if nonempty, def otherwise.

func valueOrDefault(value, def string) string {
	if value != "" {
		return value
	}
	return def
}

// Given a string of the form "host", "host:port", or "[ipv6::address]:port",
// return true if the string includes a port.
func hasPort(s string) bool { return strings.LastIndex(s, ":") > strings.LastIndex(s, "]") }

func expectsContinue(r *transportRequest) bool {
	return hasToken(getHeader(r.Header, "Expect"), "100-continue")
}

// hasToken reports whether token appears with v, ASCII
// case-insensitive, with space or comma boundaries.
// token must be all lowercase.
// v may contain mixed cased.
func hasToken(v, token string) bool {
	if len(token) > len(v) || token == "" {
		return false
	}

	if v == token {
		return true
	}

	for sp := 0; sp <= len(v)-len(token); sp++ {
		// Check that first character is good.
		// The token is ASCII, so checking only a single byte
		// is sufficient. We skip this potential starting
		// position if both the first byte and its potential
		// ASCII uppercase equivalent (b|0x20) don't match.
		// False positives ('^' => '~') are caught by EqualFold.
		if b := v[sp]; b != token[0] && b|0x20 != token[0] {
			continue
		}

		// Check that start pos is on a valid token boundary.
		if sp > 0 && !isTokenBoundary(v[sp-1]) {
			continue
		}

		// Check that end pos is on a valid token boundary.
		if endPos := sp + len(token); endPos != len(v) && !isTokenBoundary(v[endPos]) {
			continue
		}

		if strings.EqualFold(v[sp:sp+len(token)], token) {
			return true
		}
	}

	return false
}


func isTokenBoundary(b byte) bool {
	return b == ' ' || b == ',' || b == '\t'
}

// get is like Get, but key must already be in CanonicalHeaderKey form.

func getHeader(h http.Header, key string) string {
	if v := h[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func idnaASCII(v string) (string, error) {
	// TODO: Consider removing this check after verifying performance is okay.
	// Right now punycode verification, length checks, context checks, and the
	// permissible character tests are all omitted. It also prevents the ToASCII
	// call from salvaging an invalid IDN, when possible. As a result it may be
	// possible to have two IDNs that appear identical to the user where the
	// ASCII-only version causes an error downstream whereas the non-ASCII
	// version does not.
	// Note that for correct ASCII IDNs ToASCII will only do considerably more
	// work, but it will not cause an allocation.
	if isASCII(v) {
		return v, nil
	}

	return idna.Lookup.ToASCII(v)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}

	return true
}


func writerequest(r *http.Request, w io.Writer, usingProxy bool, extraHeaders http.Header, waitForContinue func() bool) (err error) {

	/*trace := httptrace.ContextClientTrace(r.Context())
	if trace != nil && trace.WroteRequest != nil {
		defer func() {
			trace.WroteRequest(httptrace.WroteRequestInfo{
				Err: err,
			})
		}()
	}*/

	// Find the target host. Prefer the Host: header, but if that
	// is not given, use the host from the request URL.
	//
	// Clean the host, in case it arrives with unexpected stuff in it.
	host := cleanHost(r.Host)

	if host == "" {
		if r.URL == nil {
			return errMissingHost
		}
		host = cleanHost(r.URL.Host)
	}

	// According to RFC 6874, an HTTP client, proxy, or other
	// intermediary must remove any IPv6 zone identifier attached
	// to an outgoing URI.
	host = removeZone(host)

	ruri := r.URL.RequestURI()
	if usingProxy && r.URL.Scheme != "" && r.URL.Opaque == "" {
		ruri = r.URL.Scheme + "://" + host + ruri
	} else if r.Method == "CONNECT" && r.URL.Path == "" {
		// CONNECT requests normally give just the host and port, not a full URL.
		ruri = host
	}

	// TODO(bradfitz): escape at least newlines in ruri?
	// Wrap the writer in a bufio Writer if it's not already buffered.
	// Don't always call NewWriter, as that forces a bytes.Buffer
	// and other small bufio Writers to have a minimum 4k buffer
	// size.
	var bw *bufio.Writer

	if _, ok := w.(io.ByteWriter); !ok {
		bw = bufio.NewWriter(w)
		w = bw
	}

	//fmt.Printf("[DEBUG] Writing Request to wire:\n")
	//fmt.Printf("%s %s HTTP/1.1\r\n", valueOrDefault(r.Method, "GET"), ruri)
	_, err = fmt.Fprintf(w, "%s %s HTTP/1.1\r\n", valueOrDefault(r.Method, "GET"), ruri)
	if err != nil {
		return err
	}

	// Header lines
	_, err = fmt.Fprintf(w, "Host: %s\r\n", host)
	if err != nil {
		return err
	}

	// Use the defaultUserAgent unless the Header contains one, which
	// may be blank to not send the header.
	// RLS - do not send in a default user agent
	userAgent := "" //defaultUserAgent
	if _, ok := r.Header["User-Agent"]; ok {
		userAgent = r.Header.Get("User-Agent")
	}
	if userAgent != "" {
		_, err = fmt.Fprintf(w, "User-Agent: %s\r\n", userAgent)
		if err != nil {
			return err
		}
	}

	// Process Body,ContentLength,Close,Trailer
	tw, err := newTransferWriter(r)
	if err != nil {
		return err
	}
	err = tw.WriteHeader(w)

	if err != nil {
		return err
	}

	err = r.Header.WriteSubset(w, reqWriteExcludeHeader)
	if err != nil {
		return err
	}

	if extraHeaders != nil {
		err = extraHeaders.Write(w)
		if err != nil {
			return err
		}
	}

	_, err = io.WriteString(w, "\r\n")

	if err != nil {
		return err
	}

	/*if trace != nil && trace.WroteHeaders != nil {
		trace.WroteHeaders()
	}*/

	// Flush and wait for 100-continue if expected.
	if waitForContinue != nil {
		if bw, ok := w.(*bufio.Writer); ok {
			err = bw.Flush()
			if err != nil {
				return err
			}
		}
		/*
		if trace != nil && trace.Wait100Continue != nil {
			trace.Wait100Continue()
		}
		*/
		if !waitForContinue() {
			closeBody(r)
			//r.closeBody()
			return nil
		}
	}

	if bw, ok := w.(*bufio.Writer); ok && tw.FlushHeaders {
		if err := bw.Flush(); err != nil {
			return err
		}
	}

	// Write body and trailer
	err = tw.WriteBody(w)

	if err != nil {
		if tw.bodyReadError == err {
			err = requestBodyReadError{err}
		}
		return err
	}

	if bw != nil {
		return bw.Flush()
	}

	return nil
}


// cleanHost cleans up the host sent in request's Host header.

//

// It both strips anything after '/' or ' ', and puts the value

// into Punycode form, if necessary.

//

// Ideally we'd clean the Host header according to the spec:

//   https://tools.ietf.org/html/rfc7230#section-5.4 (Host = uri-host [ ":" port ]")

//   https://tools.ietf.org/html/rfc7230#section-2.7 (uri-host -> rfc3986's host)

//   https://tools.ietf.org/html/rfc3986#section-3.2.2 (definition of host)

// But practically, what we are trying to avoid is the situation in

// issue 11206, where a malformed Host header used in the proxy context

// would create a bad request. So it is enough to just truncate at the

// first offending character.

func cleanHost(in string) string {
	if i := strings.IndexAny(in, " /"); i != -1 {
		in = in[:i]
	}

	host, port, err := net.SplitHostPort(in)
	if err != nil { // input was just a host
		a, err := idnaASCII(in)
		if err != nil {
			return in // garbage in, garbage out
		}
		return a
	}

	a, err := idnaASCII(host)

	if err != nil {
		return in // garbage in, garbage out
	}

	return net.JoinHostPort(a, port)
}


// removeZone removes IPv6 zone identifier from host.
// E.g., "[fe80::1%en0]:8080" to "[fe80::1]:8080"
func removeZone(host string) string {
	if !strings.HasPrefix(host, "[") {
		return host
	}

	i := strings.LastIndex(host, "]")
	if i < 0 {
		return host
	}

	j := strings.LastIndex(host[:i], "%")
	if j < 0 {
		return host
	}

	return host[:j] + host[i:]
}


// requestMethodUsuallyLacksBody reports whether the given request
// method is one that typically does not involve a request body.
// This is used by the Transport (via
// transferWriter.shouldSendChunkedRequestBody) to determine whether
// we try to test-read a byte from a non-nil Request.Body when
// Request.outgoingLength() returns -1. See the comments in
// shouldSendChunkedRequestBody.
func requestMethodUsuallyLacksBody(method string) bool {
	switch method {
	case "GET", "HEAD", "DELETE", "OPTIONS", "PROPFIND", "SEARCH":
		return true
	}
	return false
}

// FlushAfterChunkWriter signals from the caller of NewChunkedWriter
// that each chunk should be followed by a flush. It is used by the
// http.Transport code to keep the buffering behavior for headers and
// trailers, but flush out chunks aggressively in the middle for
// request bodies which may be generated slowly. See Issue 6574.
type FlushAfterChunkWriter struct {
	*bufio.Writer
}