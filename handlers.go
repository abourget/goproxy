package goproxy

// Next indicates the return values possible for handlers.
//
// In `request` handlers, `NEXT` means continue to the next handler.
// If none are left, it continues on with `FORWARD`. If you return
// `FORWARD`, then you skip all the other registered request handlers,
// and forward the request directly to the remote server, unless
// you've set a `ctx.Resp` before, in which case the response is sent
// back without touching any Response Handlers.  If you return
// `REJECT`, the library will return a 502 error to the requester.  In
// the `request` handlers, returning `MITM` will panic.
//
// In Response handlers, `NEXT` means continue with the other
// registered handlers.  If this was the last, the library will finish
// the forwarding of the current `ctx.Resp`.  When `DONE` is returned,
// the library doesn't do anything else. It assumes you have properly
// written to `ctx.ResponseWriter` with a proper response (along with
// `ctx.Req`, this would resemble closely native `net/http` request
// handling).  When `FORWARD` is returned, the lib jumps directly to
// the forwarding step, instead of going through the other response
// handlers.  When `MITM` is returned, the lib will panic.  When
// `REJECT` is returned, the lib will panic also.  You can reject a
// request, but not a response.
//
// In Connect handlers, `NEXT` means continue on with the next Connect
// handler.  `FORWARD` means continue on with forwarding the raw TCP
// socket. `MITM` means jump in the middle and try to
// man-in-the-middle the connection. With the `MITM` option, all
// future requests to be detected from within the tunnel will trigger
// the Request handlers, in the order they were registered, just like
// a normal request arriving directly outside a tunnel. Those requests
// that are MITM will have the `ctx.IsThroughMITM` property set to
// `true`.  Returning `REJECT` will reject the connection
// altogether. If you did sniff with `SNIHost()`, then the lib will
// forcefully close the connection, violating the protocol (you wanted
// to sniff, so it's your fault, right ? :).  If you didn't sniff SNI,
// then a `502 Rejected` will be sent propertly to the client before
// closing the connection. `DONE` is not valid in that context, you
// need take a decision.
type Next int

const (
	NEXT    = Next(iota) // Continue to the next Handler
	DONE                 // Implies that no further processing is required. The request has been fulfilled completely.
	FORWARD              // Continue directly with forwarding, going through Response Handlers
	MITM                 // Continue with Man-in-the-middle attempt, either through HTTP or HTTPS.
	REJECT               // Reject the CONNECT attempt outright
)

// About CONNECT requests

type Handler interface {
	Handle(ctx *ProxyCtx) Next
}

type HandlerFunc func(ctx *ProxyCtx) Next

func (f HandlerFunc) Handle(ctx *ProxyCtx) Next {
	return f(ctx)
}

type ChainedHandler func(Handler) Handler

var AlwaysMitm = HandlerFunc(func(ctx *ProxyCtx) Next {
	ctx.SNIHost()
	return MITM
})

var AlwaysReject = HandlerFunc(func(ctx *ProxyCtx) Next {
	return REJECT
})

var AlwaysForward = HandlerFunc(func(ctx *ProxyCtx) Next {
	return FORWARD
})
