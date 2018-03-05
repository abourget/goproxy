package goproxy

import (
	"fmt"
	"net/http"
	"path/filepath"
	//"strings"
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

	// We haven't made a connection to the destination site yet. Here we're just hijacking
	// the connection back to the local client.
	hij, ok := ctx.ResponseWriter.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}

	// This sets up a new connection to the original client
	conn, _, err := hij.Hijack()
	if err != nil {
		panic("cannot hijack connection " + err.Error())
	}

	ctx.Conn = conn

	var then Next


	for _, handler := range proxy.connectHandlers {
		
		then = handler.Handle(ctx)

		switch then {
		case NEXT:
			continue

		case FORWARD:
			// Don't record allowed metrics for whitelisted sites
			break

		case MITM:
			//ctx.Logf("  *** UpdatedAllowedCounter")
			if ctx.Resp != nil && ctx.Resp.StatusCode != 206 {
				ctx.Proxy.UpdateAllowedCounter()
			}

			err := ctx.ManInTheMiddle()
			if err != nil {
				ctx.Logf(1, "ERROR: Couldn't MITM: %s", err)
			}
			return

		case REJECT:
			//ctx.Logf("  *** UpdatedBlockedCounter")

			ctx.Proxy.UpdateBlockedCounter()
			ctx.Proxy.UpdateBlockedHosts(ctx.Req.Host)
			ctx.RejectConnect()

			// What happens if we don't return anything?
			return
		case SIGNATURE:
			//ctx.Logf(1, "  *** dispatchConnectHandlers:SIGNATURE")
			//ctx.ReturnSignature()
			return
		case DONE:
			return

		default:
			panic(fmt.Sprintf("Invalid value %v for Next after calling %v", then, handler))
		}
	}

	/*if strings.Contains(ctx.host, "js-agent.newrelic.com") {
		ctx.Logf(1, "  *** js-agent.newrelic.com forward request")
	}*/
	if err := ctx.ForwardConnect(); err != nil {
		ctx.Logf(1, "ERROR: Failed forwarding in fallback clause: %s", err)
	}

}

func (proxy *ProxyHttpServer) dispatchRequestHandlers(ctx *ProxyCtx) {


	var then Next
	for _, handler := range proxy.requestHandlers {
		then = handler.Handle(ctx)
		switch then {
		case DONE:
			//if log {
			//	ctx.Logf(1, " *** DONE ***")
			//}
			ctx.DispatchDoneHandlers()
			return
		case MOCK:
			ctx.DispatchResponseHandlers()
			return
		case NEXT:
			//if log {
			//	ctx.Logf(1, " *** NEXT ***")
			//}
			continue
		case FORWARD:
			//if log {
			//	ctx.Logf(1, " *** FORWARD ***")
			//}
			if ctx.Resp != nil {
				// We've got a Resp already, so short circuit the ResponseHandlers.
				ctx.ForwardResponse(ctx.Resp)
				return
			}
			break
		case MITM:
			panic("MITM doesn't make sense when we are already parsing the request")
		case SIGNATURE:
			//ctx.Logf(1, "  *** dispatchRequestHandlers:SIGNATURE")
			ctx.ReturnSignature()
			ctx.ForwardResponse(ctx.Resp)
			return
		case REJECT:
				ctx.Proxy.UpdateBlockedCounter()
				ctx.Proxy.UpdateBlockedHosts(ctx.Req.Host)

				ext := filepath.Ext(ctx.Req.URL.Path)
				//ctx.Logf("  path: %s  extension: %s", ctx.Req.URL.Path, ext)
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
					//ctx.Logf("  Serving 502")
					ctx.NewResponse(502, "text/plain; charset=utf-8", "502.1 Blocked by Winston [" + ext + "]")
				}

				ctx.ForwardResponse(ctx.Resp)


			return
		default:
			panic(fmt.Sprintf("Invalid value %v for Next after calling %v", then, handler))
		}
	}


	ctx.ForwardRequest(ctx.host)
	ctx.DispatchResponseHandlers()
}
