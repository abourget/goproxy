package goproxy

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"time"
	"net/http/httptest"
)

func TestRequestTracer(t *testing.T) {
	Convey("RequestTracer works", t, func() {
		tr := &RequestTracer{}
		//So(tr.Requests, ShouldNotEqual, nil)
		So(len(tr.Requests), ShouldEqual, 0)

		tr.RequestTrace([]byte("getpage.aspx"), 0)
		So(len(tr.Requests), ShouldEqual, 1)

		req := tr.Requests[0]
		So(req.expires, ShouldHappenAfter, time.Now().Add(time.Second * 100))

		// Create a new ctx object. We only need the Req property.
		URL := "https://microsoft.com/test/notourpage.aspx?query=213"
		r := httptest.NewRequest("GET", URL, nil)
		ctx := &goproxy.ProxyCtx{
			Req:            r,
		}

		shouldTrace := tr.Trace(ctx)
		So(shouldTrace, ShouldEqual, false)

		// This should match
		URL = "https://microsoft.com/test/getpage.aspx?query=213"
		r = httptest.NewRequest("GET", URL, nil)
		ctx = &goproxy.ProxyCtx{
			Req:            r,
		}

		shouldTrace = tr.Trace(ctx)
		So(shouldTrace, ShouldEqual, true)

		// Repeat the trace request. It should not match.
		shouldTrace = tr.Trace(ctx)
		So(shouldTrace, ShouldEqual, false)
		So(len(tr.Requests), ShouldEqual, 0)

	})
}