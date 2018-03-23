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
	// RLS 2/16/2018 - This is where requests are made to the original destination sites.

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
				Proxy: ctx.Proxy.Transport.Proxy,
			}
			addendum = append(addendum, fmt.Sprintf(", sni=%q, fakedns=%q", transport.TLSClientConfig.ServerName, ctx.fakeDestinationDNS))
			tr = transport
		} else {
			// RLS 3/20/2018 - route the request through the privacy network.
			// TODO: How to handle failures?
			// TODO: Select which transport to use
			if ctx.PrivateNetwork && len(ctx.Proxy.PrivateTransport) > 0 {
				//fmt.Printf("  *** RoundTrip() - Routing through private network\n")
				tr = ctx.Proxy.PrivateTransport[0]
			} else {
				tr = ctx.Proxy.Transport
			}
		}

		if ctx.Proxy.FlushIdleConnections {
			ctx.Proxy.Transport.CloseIdleConnections()
			ctx.Proxy.FlushIdleConnections = false
		}

		ctx.RoundTripper = ctx.wrapTransport(tr)
	}

	if ctx.isLogEnabled {
		addendum = append(addendum, "log=yes")
	}

	resp, err := ctx._roundTripWithLog(req)
	//ctx.Logf("  RoundTrip returned: err=%v", err)

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
		if reqAndResp.captureContent && req.ContentLength > 0 {
			req, reqAndResp.req = copyReq(req)
		} else {
			reqAndResp.req = req
		}

		resp, err = ctx.RoundTripper.RoundTrip(req, ctx)

		if reqAndResp.captureContent && resp != nil && resp.ContentLength != 0 {
			resp, reqAndResp.resp = copyResp(resp)
		} else {
			reqAndResp.resp = resp
		}

		reqAndResp.end = time.Now()
		ctx.Proxy.harLogEntryCh <- *reqAndResp

	} else {
		resp, err = ctx.RoundTripper.RoundTrip(req, ctx)
	}

	return resp, err
}

func (ctx *ProxyCtx) wrapTransport(tr *http.Transport) RoundTripper {
	return RoundTripperFunc(func(req *http.Request, ctx *ProxyCtx) (*http.Response, error) {
		/*if strings.Contains(req.URL.String(), "howsmyssl") {
			fmt.Printf("  *** TLSClientConfig: %+v\n\n", tr.TLSClientConfig)
		}*/

		return tr.RoundTrip(req)
	})
}
