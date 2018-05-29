package goproxy

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
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
			// Don't update allowed metrics for whitelisted sites
			break

		case MITM:
			err := ctx.ManInTheMiddle()
			if err != nil {
				ctx.Logf(1, "ERROR: Couldn't MITM: %s", err)
			}
			return

		case REJECT:
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

	/*if strings.Contains(ctx.host, "facebook.com") {
		ctx.Logf(1, "  *** js-agent.newrelic.com forward request")
	}*/
	if err := ctx.ForwardConnect(); err != nil {
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
					//ctx.NewResponse(502, "text/plain; charset=utf-8", "502.1 Blocked by Winston [" + ext + "]")

					title := "Tracker Blocked"
					errorcode := "504 Blocked by Winston"
					text := "A website is attempting to track you. For your protection, access to this page has been blocked. It’s recommended that you do NOT visit this site."
					proceed := "<a href=\"#\" onclick=\"buildURL();return false;\">Visit this page anyway</a>"
					/*// Friendly error logging
					if ctx.ResponseError != nil {
						switch ctx.ResponseError.Error() {
						case "x509: certificate signed by unknown authority":
							title = "Website blocked"
							errorcode = "Certificate signed by unknown authority"
							text = "The certificate issued by this website was issued by an unknown authority. For your protection, access to this page has been blocked."
							proceed = ""
						}
					}*/

					body := strings.Replace(blockedhtml, "%BLOCKED%", errorcode, 1)
					body = strings.Replace(body, "%TITLE%", title, 1)
					body = strings.Replace(body, "%TEXT%", text, 1)
					body = strings.Replace(body, "%PROCEED%", proceed, 1)
					//ctx.NewResponse(504, "text/plain; charset=utf-8", "504 Blocked by Winston / No response from server")
					ctx.NewResponse(504, "text/html; charset=utf-8", body)



					//ctx.NewResponse(504, "text/html; charset=utf-8", strings.Replace(blockedhtml, "Blocked", "502.1 Blocked by Winston", 1))
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
