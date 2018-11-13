package goproxy

import (
	"testing"
	. "github.com/smartystreets/goconvey/convey"
	"time"
	"net/http/httptest"
	"strings"
	//"fmt"
)

func TestTracerModified(t *testing.T) {
	Convey("RequestTracer - Modify parameter works", t, func() {
		tr := &RequestTracer{}
		//So(tr.Requests, ShouldNotEqual, nil)
		So(len(tr.Requests), ShouldEqual, 0)

		cmd := strings.Split("trace getpage.aspx modified", " ")

		tr.RequestTrace(cmd[1:], 0)
		So(len(tr.Requests), ShouldEqual, 1)

		req := tr.Requests[0]
		So(req.expires, ShouldHappenAfter, time.Now().Add(time.Second * 100))

		// Create a new ctx object. We only need the Req property.
		URL := "https://microsoft.com/test/notourpage.aspx?query=213"
		r := httptest.NewRequest("GET", URL, nil)
		ctx := &ProxyCtx{
			Req:            r,
		}

		tracerequest := tr.Trace(ctx)
		So(tracerequest, ShouldNotEqual, nil)
		So(tracerequest.Modified, ShouldEqual, false)

		//fmt.Println("[TEST] 2nd request - Should match")
		// This should match
		URL = "https://microsoft.com/test/getpage.aspx?query=213"
		r = httptest.NewRequest("GET", URL, nil)
		ctx = &ProxyCtx{
			Req:            r,
		}

		tracerequest = tr.Trace(ctx)
		So(tracerequest, ShouldNotEqual, nil)
		So(tracerequest.Modified, ShouldEqual, true)

		//fmt.Println("[TEST] 3rd request - Should not match")
		// Repeat the trace request. It should not match.
		tracerequest = tr.Trace(ctx)
		So(len(tr.Requests), ShouldEqual, 0)
		So(tracerequest.Modified, ShouldEqual, false)


	})

	// Unmodified flag automatically sets the modified flag
	Convey("RequestTracer - Unmodified parameter works", t, func() {
		tr := &RequestTracer{}
		//So(tr.Requests, ShouldNotEqual, nil)
		So(len(tr.Requests), ShouldEqual, 0)

		cmd := strings.Split("trace getpage.aspx unmodified", " ")

		tr.RequestTrace(cmd[1:], 0)
		So(len(tr.Requests), ShouldEqual, 1)

		req := tr.Requests[0]
		So(req.expires, ShouldHappenAfter, time.Now().Add(time.Second * 100))

		// Create a new ctx object. We only need the Req property.
		URL := "https://microsoft.com/test/notourpage.aspx?query=213"
		r := httptest.NewRequest("GET", URL, nil)
		ctx := &ProxyCtx{
			Req:            r,
		}

		tracerequest := tr.Trace(ctx)
		So(tracerequest, ShouldNotEqual, nil)
		So(tracerequest.Modified, ShouldEqual, false)
		So(tracerequest.Unmodified, ShouldEqual, false)

		//fmt.Println("[TEST] 2nd request - Should match")
		// This should match
		URL = "https://microsoft.com/test/getpage.aspx?query=213"
		r = httptest.NewRequest("GET", URL, nil)
		ctx = &ProxyCtx{
			Req:            r,
		}

		tracerequest = tr.Trace(ctx)
		So(tracerequest, ShouldNotEqual, nil)
		So(tracerequest.Modified, ShouldEqual, true)
		So(tracerequest.Unmodified, ShouldEqual, true)

		//fmt.Println("[TEST] 3rd request - Should not match")
		// Repeat the trace request. It should not match.
		tracerequest = tr.Trace(ctx)
		So(len(tr.Requests), ShouldEqual, 0)
		So(tracerequest.Modified, ShouldEqual, false)
		So(tracerequest.Unmodified, ShouldEqual, false)


	})

	Convey("RequestTracer - SkipRequest and SkipResponse parameters work", t, func() {
		tr := &RequestTracer{}
		//So(tr.Requests, ShouldNotEqual, nil)
		So(len(tr.Requests), ShouldEqual, 0)

		cmd := strings.Split("trace getpage.aspx skiprequest skipresponse", " ")

		tr.RequestTrace(cmd[1:], 0)
		So(len(tr.Requests), ShouldEqual, 1)

		req := tr.Requests[0]
		So(req.expires, ShouldHappenAfter, time.Now().Add(time.Second * 100))

		// Create a new ctx object. We only need the Req property.
		URL := "https://microsoft.com/test/notourpage.aspx?query=213"
		r := httptest.NewRequest("GET", URL, nil)
		ctx := &ProxyCtx{
			Req:            r,
		}

		tracerequest := tr.Trace(ctx)
		So(tracerequest, ShouldNotEqual, nil)
		So(tracerequest.SkipRequest, ShouldEqual, false)
		So(tracerequest.SkipResponse, ShouldEqual, false)

		//fmt.Println("[TEST] 2nd request - Should match")
		// This should match
		URL = "https://microsoft.com/test/getpage.aspx?query=213"
		r = httptest.NewRequest("GET", URL, nil)
		ctx = &ProxyCtx{
			Req:            r,
		}

		tracerequest = tr.Trace(ctx)
		So(tracerequest, ShouldNotEqual, nil)
		So(tracerequest.SkipRequest, ShouldEqual, true)
		So(tracerequest.SkipResponse, ShouldEqual, true)

		// Repeat the trace request. It should still match.
		tracerequest = tr.Trace(ctx)
		So(tracerequest.SkipRequest, ShouldEqual, true)
		So(tracerequest.SkipResponse, ShouldEqual, true)


	})

	Convey("Second request to tracer overwrites previous one", t, func() {
		tr := &RequestTracer{}
		//So(tr.Requests, ShouldNotEqual, nil)
		So(len(tr.Requests), ShouldEqual, 0)

		cmd := strings.Split("trace chicagotribune skiprequest", " ")

		tr.RequestTrace(cmd[1:], 0)
		So(len(tr.Requests), ShouldEqual, 1)

		req := tr.Requests[0]
		So(req.expires, ShouldHappenAfter, time.Now().Add(time.Second * 100))

		// Create a new ctx object. We only need the Req property.
		URL := "https://chicagotribune.com"
		r := httptest.NewRequest("GET", URL, nil)
		ctx := &ProxyCtx{
			Req:            r,
		}

		tracerequest := tr.Trace(ctx)
		So(tracerequest, ShouldNotEqual, nil)
		So(tracerequest.SkipRequest, ShouldEqual, true)
		So(tracerequest.SkipResponse, ShouldEqual, false)


		cmd = strings.Split("trace chicagotribune skipresponse", " ")
		tr.RequestTrace(cmd[1:], 0)
		So(len(tr.Requests), ShouldEqual, 1)

		URL = "https://chicagotribune.com"
		r = httptest.NewRequest("GET", URL, nil)
		ctx = &ProxyCtx{
			Req:            r,
		}

		tracerequest = tr.Trace(ctx)
		So(tracerequest, ShouldNotEqual, nil)
		So(tracerequest.SkipRequest, ShouldEqual, false)
		So(tracerequest.SkipResponse, ShouldEqual, true)


	})
}