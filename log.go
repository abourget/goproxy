// Provides a mechanism for requests to buffer output for later retrieval.

package goproxy

import (
	"time"
	"fmt"
	"sync"
)

// Implements a buffered log, allowing clients to subscribe to a particular client log
// Currently only supports one active subscriber. These have to be global so they are
// shared by all active proxies.
var bufferedlogmu 		sync.Mutex
var bufferedLog 		[]string
var currentlogsignature 	string
var bufferedlogdeadline 	time.Time


// Logf prints a message to the proxy's log. Should be used in a ProxyHttpServer's filter
// This message will be printed only if the Verbose field of the ProxyHttpServer is set to true
func (ctx *ProxyCtx) Logf(level uint16, msg string, argv ...interface{}) {
	// RLS 2/10/2018 - Changed to bitmask so that we can toggle the different log levels.
	bitflag := uint16(1 << uint16((level - 1)))
	if ctx.Proxy.Verbose && (level == 0 || ctx.Proxy.VerbosityLevel&bitflag != 0) {
		ctx.printf(msg, argv...)
	}

	if ctx.Proxy != nil {
		formattedmsg := fmt.Sprintf("[%03d] "+msg+"\n", append([]interface{}{ctx.Session & 0xFF}, argv...)...)
		ctx.Proxy.BufferLogEntry(ctx.CipherSignature, formattedmsg)
	}
}

// Warnf prints a message to the proxy's log. Should be used in a ProxyHttpServer's filter
// This message will always be printed.
func (ctx *ProxyCtx) Warnf(msg string, argv ...interface{}) {
	ctx.Logf(6, "WARN: "+msg, argv...)
}

func (ctx *ProxyCtx) printf(msg string, argv ...interface{}) {
	ctx.Proxy.Logger.Printf("[%03d] "+msg+"\n", append([]interface{}{ctx.Session & 0xFF}, argv...)...)
}


// RLS 8/16/2017
// Logging now supports multiple levels of verbosity
func (proxy *ProxyHttpServer) Logf(level uint16, msg string, v ...interface{}) {
	if proxy.Logger != nil {
		if proxy.Verbose {}
		if level == 0 || proxy.VerbosityLevel&level != 0 {
			proxy.Logger.Printf(msg+"\n", v...)
		}
	}
}

//bufferedlogmu 		sync.Mutex
//bufferedLog 		[]string
//currentlogsignature 	string
//bufferedlogdeadline 	time.Time

// Retrieves the log entries for the given signature since the prior call. If there was no
// prior call, it begins buffering log entries for the next 30 seconds. The client must
// poll this function more frequently to obtain a complete log.
func (proxy *ProxyHttpServer) GetLogEntries(signature string) []string {
	bufferedlogdeadline = time.Now().Add(30 * time.Second)
	if currentlogsignature != signature || bufferedlogdeadline.Before(time.Now()) {
		// The signature is changing or we timed out. Either way, reset the buffered log
		currentlogsignature = signature
		bufferedlogdeadline = time.Now().Add(30 * time.Second)
		bufferedlogmu.Lock()
		bufferedLog = nil
		defer bufferedlogmu.Unlock()
		return []string{}

	}

	bufferedlogmu.Lock()
	defer bufferedlogmu.Unlock()

	log := bufferedLog
	bufferedLog = nil
	return log
}

func (proxy *ProxyHttpServer) BufferLogEntry(signature, entry string) {
	if bufferedlogdeadline.After(time.Now()) && signature == currentlogsignature  {
		bufferedlogmu.Lock()
		defer bufferedlogmu.Unlock()
		bufferedLog = append(bufferedLog, entry)
	}
}

