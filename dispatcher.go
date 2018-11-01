package goproxy

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	//"io"
	//"bufio"
	//"bytes"
)

// HandleConnectFunc and HandleConnect mimic the `net/http` handlers,
// and register handlers for CONNECT proxy calls.
//
// See `Next` values for the return value meaning
func (proxy *ProxyHttpServer) HandleConnectFunc(f func(ctx *ProxyCtx) Next) {
	proxy.connectHandlers = append(proxy.connectHandlers, HandlerFunc(f))
}

func (proxy *ProxyHttpServer) HandleConnect(f Handler) {
	proxy.connectHandlers = append(proxy.connectHandlers, f)
}

// HandleRequestFunc and HandleRequest put hooks to handle certain
// requests. Note that MITM'd and HTTP requests that go through a
// CONNECT'd connection also go through those Request Handlers.
//
// See `Next` values for the return value meaning
func (proxy *ProxyHttpServer) HandleRequestFunc(f func(ctx *ProxyCtx) Next) {
	proxy.requestHandlers = append(proxy.requestHandlers, HandlerFunc(f))
}

func (proxy *ProxyHttpServer) HandleRequest(f Handler) {
	proxy.requestHandlers = append(proxy.requestHandlers, f)
}

// HandleResponseFunc and HandleResponse put hooks to handle certain
// requests. Note that MITM'd and HTTP requests that go through a
// CONNECT'd connection also go through those Response Handlers.
//
// See `Next` values for the return value meaning
func (proxy *ProxyHttpServer) HandleResponseFunc(f func(ctx *ProxyCtx) Next) {
	proxy.responseHandlers = append(proxy.responseHandlers, HandlerFunc(f))
}

func (proxy *ProxyHttpServer) HandleResponse(f Handler) {
	proxy.responseHandlers = append(proxy.responseHandlers, f)
}

// HandleDoneFunc and HandleDone are called at the end of every request.
// Use them to cleanup.
//
// See `Next` values for the return value meaning
func (proxy *ProxyHttpServer) HandleDoneFunc(f func(ctx *ProxyCtx) Next) {
	proxy.doneHandlers = append(proxy.doneHandlers, HandlerFunc(f))
}

func (proxy *ProxyHttpServer) HandleDone(f Handler) {
	proxy.doneHandlers = append(proxy.doneHandlers, f)
}

//////
////// dispatchers section //////
//////

func (proxy *ProxyHttpServer) dispatchConnectHandlers(ctx *ProxyCtx) {

	//fmt.Printf("[DEBUG] dispatchConnectHandlers() [%s]\n", ctx.host)
	//trace := false
	//if strings.Contains(ctx.host, "winston.conf") {
	//	trace = true
	//}
	// We haven't made a connection to the destination site yet. Here we're just hijacking
	// the connection back to the local client.
	hij, ok := ctx.ResponseWriter.(http.Hijacker)
	if !ok {
		//fmt.Printf("[DEBUG] dispatchConnectHandlers() err 1\n")
		panic("httpserver does not support hijacking")
	}

	// This sets up a new connection to the original client
	conn, _, err := hij.Hijack()
	if err != nil {
		//fmt.Printf("[DEBUG] dispatchConnectHandlers() err 2\n")
		fmt.Printf("[DEBUG] dispatchConnectHandlers() Hijack error [%s]\n", ctx.host, err)
		panic("cannot hijack connection " + err.Error())
	}

	ctx.Conn = conn

	var then Next

	for _, handler := range proxy.connectHandlers {
		//if trace {
		//	fmt.Printf("[DEBUG] dispatchConnectHandlers() Loop [%s]\n", ctx.host)
		//}
		then = handler.Handle(ctx)

		switch then {
		case NEXT:
			continue

		case FORWARD:
			// Don't update allowed metrics for whitelisted sites
			//if trace {
			//	fmt.Printf("[DEBUG] dispatchConnectHandlers() - FORWARD. [%s]\n", ctx.host)
			//}
			break

		case MITM:
			//if trace {
			//	fmt.Printf("[DEBUG] dispatchConnectHandlers() - MITM. [%s]\n", ctx.host)
			//}
			err := ctx.ManInTheMiddle()
			if err != nil {
				ctx.Logf(1, "ERROR: Couldn't MITM: %s", err)
			}

			return

		case REJECT:
			//if trace {
			//	fmt.Printf("[DEBUG] dispatchConnectHandlers() - REJECT. [%s]\n", ctx.host)
			//}
			ctx.RejectConnect()

			// What happens if we don't return anything?
			return
		case SIGNATURE:
			return
		case DONE:
			return
		default:
			panic(fmt.Sprintf("Invalid value %v for Next after calling %v", then, handler))
		}
	}

	//if trace {
	//	fmt.Printf("[DEBUG] dispatchConnectHandlers() - about to call ForwardConnect(). [%s]\n", ctx.host)
	//}

	if err := ctx.ForwardConnect(); err != nil {
		//if trace {
		//	fmt.Printf("[DEBUG] dispatchConnectHandlers() - err from ForwardConnect(). [%s]\n", ctx.host, err)
		//}
		ctx.Logf(1, "ERROR: Failed forwarding in fallback clause: %s", err)
	}

}

// RLS 5/22/2018 - exported so that we can use it for unit testing
func (proxy *ProxyHttpServer) DispatchRequestHandlers(ctx *ProxyCtx) {
	var then Next
	for _, handler := range proxy.requestHandlers {
		then = handler.Handle(ctx)
		switch then {
		case DONE:
			ctx.DispatchDoneHandlers()
			return
		case MOCK:
			ctx.DispatchResponseHandlers()
			return
		case NEXT:
			continue
		case FORWARD:
			if ctx.Resp != nil {
				// We've got a Resp already, so short circuit the ResponseHandlers.
				ctx.ForwardResponse(ctx.Resp)
				return
			}
			break
		case MITM:
			panic("MITM doesn't make sense when we are already parsing the request")
		//case WELCOME:
		//	// Test - 302 redirect them to winston homepage
		//
		//	title := "Welcome to Winston"
		//	errorcode := "302 Found"
		//	text := "Welcome to Winston"
		//	proceed := ""
		//
		//	body := strings.Replace(blockedhtml, "%BLOCKED%", errorcode, 1)
		//	body = strings.Replace(body, "%TITLE%", title, 1)
		//	body = strings.Replace(body, "%TEXT%", text, 1)
		//	body = strings.Replace(body, "%PROCEED%", proceed, 1)
		//	ctx.NewResponse(302, "text/html; charset=utf-8", body)
		//
		//	// slice port from host
		//	host := ctx.Host()
		//	if i := strings.Index(host, ":") ; i != -1 {
		//		host = host[:i]
		//	}
		//
		//	redirecturl := "http://winston.conf/pages/welcome?url=" + host
		//	ctx.Resp.Header.Set("Location", redirecturl)
		//	ctx.Resp.Header.Add("Set-Cookie", "winston=yes; domain=winston.conf; Max-Age=3600;")
		//	ctx.ForwardResponse(ctx.Resp)
		//
		//	return

		case REJECT:
			ext := filepath.Ext(ctx.Req.URL.Path)
			//fmt.Printf("[DEBUG] DispatchRequestHandlers() - REJECT. [%s]\n", ctx.host)
			switch ext {
			case ".js":
				//ctx.Logf("  Serving dummy script")
				ctx.NewEmptyScript()
			case ".png", ".gif":
				//ctx.Logf("  Serving dummy %s", ext)
				ctx.NewEmptyImage(ext)
			default:
				// Note that jpg pixels are > 1k in length and are rarely used
				// so we just return a 502 error to avoid the bandwidth.
				// Todo: Revisit this if we're seeing too many broken image icons in web pages

				title := "Tracker Blocked"
				errorcode := "504 Blocked by Winston"
				text := "A website is attempting to track you. For your protection, access to this page has been blocked. It’s recommended that you do NOT visit this site."
				proceed := "<a href=\"#\" onclick=\"buildURL();return false;\">Visit this page anyway</a>"

				body := strings.Replace(blockedhtml, "%BLOCKED%", errorcode, 1)
				body = strings.Replace(body, "%TITLE%", title, 1)
				body = strings.Replace(body, "%TEXT%", text, 1)
				body = strings.Replace(body, "%PROCEED%", proceed, 1)
				//ctx.NewResponse(504, "text/plain; charset=utf-8", "504 Blocked by Winston / No response from server")
				ctx.NewResponse(504, "text/html; charset=utf-8", body)
			}

			ctx.ForwardResponse(ctx.Resp)


			return
		default:
			panic(fmt.Sprintf("Invalid value %v for Next after calling %v", then, handler))
		}
	}

	if ctx.IsNonHttpProtocol {
		// This forwards the request and pipes the response back to the client, similar to ForwardConnect()
		// We don't process the response in any way (yet).
		ctx.ForwardNonHTTPRequest(ctx.host)
	} else {
		// If we're tracing, we need to copy the original headers so that we can duplicate the request
		if ctx.Trace {
			ctx.TraceInfo.originalheaders = make(map[string]string)
			for name, headers := range ctx.Req.Header {
				for _, h := range headers {
					ctx.TraceInfo.originalheaders[name] = h
				}
			}
		}

		ctx.ForwardRequest(ctx.host)


		ctx.DispatchResponseHandlers()
	}
}
