package goproxy_test

import (
	. "github.com/smartystreets/goconvey/convey"
	"github.com/winstonprivacyinc/winston/goproxy"
	"net/http/httptest"
	"testing"
)

func TestRequestLogger(t *testing.T) {
	Convey("Log buffering works", t, func() {
		// Set up proxy object
		proxy := goproxy.NewProxyHttpServer()
		ctx := GetCTX("https://www.howsmyssl.com", "", proxy)

		// Set up ctx object
		signature1 := "testclient1"
		signature2 := "testclient2"
		ctx.CipherSignature = signature1

		// Log a message with a test client
		message1 := "Hello, World!"
		ctx.Logf(1, message1)

		// Get log
		result := ctx.Proxy.GetLogEntries(signature1)

		// Results should be empty
		So(len(result), ShouldEqual, 0)

		// Log another message
		message2 := "Hello, World! Take two."
		ctx.Logf(1, message2)

		// Get log - message should be there
		result = ctx.Proxy.GetLogEntries(signature1)
		So(len(result), ShouldEqual, 1)
		So(result[0], ShouldContainSubstring, message2)

		// Get log again - should return nothing
		result = ctx.Proxy.GetLogEntries(signature1)
		So(len(result), ShouldEqual, 0)

		// Log two messages
		message3 := "Hello, World! Part III."
		message4 := "Revenge of Hello, World!"
		ctx.Logf(1, message3)
		ctx.Logf(1, message4)

		// Get log - both messages should be there
		result = ctx.Proxy.GetLogEntries(signature1)
		So(len(result), ShouldEqual, 2)
		So(result[0], ShouldContainSubstring, message3)
		So(result[1], ShouldContainSubstring, message4)

		// Log a message
		message5 := "Hello, World! vs. Superman"
		ctx.Logf(1, message5)

		// Get log with a new client signature - should return nothing
		result = ctx.Proxy.GetLogEntries(signature2)
		So(len(result), ShouldEqual, 0)

		// Log a message with first client
		ctx.Logf(1, message1)

		// Get log - should return nothing
		result = ctx.Proxy.GetLogEntries(signature2)
		So(len(result), ShouldEqual, 0)

		// Log a message with second client
		ctx.CipherSignature = signature2
		ctx.Logf(1, message2)

		// Get log - should return the message
		result = ctx.Proxy.GetLogEntries(signature2)
		So(len(result), ShouldEqual, 1)
		So(result[0], ShouldContainSubstring, message2)
	})
}

func GetCTX(URL string, useragent string, proxy *goproxy.ProxyHttpServer) goproxy.ProxyCtx {
	// Create a context object to use for the following tests
	r := httptest.NewRequest("GET", URL, nil)

	w := httptest.NewRecorder()
	ctx := goproxy.ProxyCtx{
		Method:          r.Method,
		SourceIP:        r.RemoteAddr, // pick it from somewhere else ? have a plugin to override this ?
		Req:             r,
		ResponseWriter:  w,
		UserData:        make(map[string]string),
		UserObjects:     make(map[string]interface{}),
		Session:         1,
		Proxy:           proxy,
		MITMCertConfig:  proxy.MITMCertConfig,
		Tlsfailure:      proxy.Tlsfailure,
		VerbosityLevel:  proxy.VerbosityLevel,
		DeviceType:      -1,
		CipherSignature: "xyz123",
		//Host:	r.URL.Host,
	}

	return ctx

}
