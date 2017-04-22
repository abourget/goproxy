package goproxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type RoundTripper interface {
	RoundTrip(req *http.Request, ctx *ProxyCtx) (*http.Response, error)
}

type RoundTripperFunc func(req *http.Request, ctx *ProxyCtx) (*http.Response, error)

func (f RoundTripperFunc) RoundTrip(req *http.Request, ctx *ProxyCtx) (*http.Response, error) {
	return f(req, ctx)
}

func (ctx *ProxyCtx) RoundTrip(req *http.Request) (*http.Response, error) {
	var tr *http.Transport
	var addendum = []string{""}

	// Redirect with Fake Destination ?
	if ctx.RoundTripper == nil {
		if ctx.fakeDestinationDNS != "" {
			req.URL.Host = ctx.fakeDestinationDNS
			transport := &http.Transport{
				TLSClientConfig: &tls.Config{
					ServerName:         strings.Split(ctx.host, ":")[0],
					InsecureSkipVerify: true,
				},
				Proxy: ctx.proxy.Transport.Proxy,
			}
			addendum = append(addendum, fmt.Sprintf(", sni=%q, fakedns=%q", transport.TLSClientConfig.ServerName, ctx.fakeDestinationDNS))
			tr = transport
		} else {
			tr = ctx.proxy.Transport
		}

		ctx.RoundTripper = ctx.wrapTransport(tr)
	}

	if ctx.isLogEnabled {
		addendum = append(addendum, "log=yes")
	}

	ctx.Logf("RoundTrip for req.URL=%q, req.Host=%q%s", req.URL, req.Host, strings.Join(addendum, ", "))

	resp, err := ctx._roundTripWithLog(req)
	ctx.Logf("  RoundTrip returned: err=%v", err)

	return resp, err
}

func (ctx *ProxyCtx) _roundTripWithLog(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	if ctx.isLogEnabled == true {
		reqAndResp := new(harReqAndResp)
		reqAndResp.start = time.Now()
		reqAndResp.captureContent = ctx.isLogWithContent

		req := ctx.Req
		if req.ContentLength > 0 {
			req, reqAndResp.req = copyReq(req)
		} else {
			reqAndResp.req = req
		}

		resp, err = ctx.RoundTripper.RoundTrip(req, ctx)

		if resp != nil && resp.ContentLength != 0 {
			resp, reqAndResp.resp = copyResp(resp)
		} else {
			reqAndResp.resp = resp
		}

		reqAndResp.end = time.Now()
		ctx.proxy.harLogEntryCh <- *reqAndResp

	} else {
		resp, err = ctx.RoundTripper.RoundTrip(req, ctx)
	}

	return resp, err
}

func (ctx *ProxyCtx) wrapTransport(tr *http.Transport) RoundTripper {
	return RoundTripperFunc(func(req *http.Request, ctx *ProxyCtx) (*http.Response, error) {
		return tr.RoundTrip(req)
	})
}
