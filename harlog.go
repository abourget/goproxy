package goproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/abourget/goproxy/har"
)

func (proxy *ProxyHttpServer) harLogAggregator() {
	proxy.Logf("Launching harLogAggregator()")
	for {
		select {
		case reqAndResp := <-proxy.harLogEntryCh:

			harEntry := new(har.Entry)
			harEntry.Request = har.ParseRequest(reqAndResp.req, reqAndResp.captureContent)
			harEntry.StartedDateTime = reqAndResp.start
			harEntry.Response = har.ParseResponse(reqAndResp.resp, reqAndResp.captureContent)
			harEntry.Time = reqAndResp.end.Sub(reqAndResp.start).Nanoseconds() / 1e6
			harEntry.FillIPAddress(reqAndResp.req) // should take it from the actual conn?
			if len(proxy.harLog.Log.Entries) == 0 {
				proxy.harLog.AppendPage(har.Page{
					ID:              "0",
					StartedDateTime: harEntry.StartedDateTime,
					Title:           "GoProxy Log",
				})
			}
			harEntry.PageRef = "0"
			proxy.harLog.AppendEntry(*harEntry)

		case filename := <-proxy.harFlushRequest:
			proxy.Logf("Received HAR flush request to %q", filename)
			if len(proxy.harLog.Log.Entries) == 0 {
				proxy.Logf("No HAR entries to flush")
				continue
			}

			err := flushHarToDisk(proxy.harLog, filename)
			if err != nil {
				proxy.Logf("Error flushing HAR file to disk: %s", err)
			} else {
				proxy.Logf("Wrote HAR file to disk: %s", filename)
			}

			proxy.harLog = har.New() // reset
		case memory := <-proxy.harFlushToMemory:
			proxy.Logf("Received HAR flush request to memory")
			if len(proxy.harLog.Log.Entries) == 0 {
				proxy.Logf("No HAR entries to flush")
				continue
			}
			memory <-proxy.harLog
		}

	}
}

func flushHarToDisk(har *har.Har, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	jsonHar, err := json.MarshalIndent(har, "", "  ")
	if err != nil {
		return err
	}

	_, err = file.Write(jsonHar)
	if err != nil {
		return err
	}

	return nil
}

type harReqAndResp struct {
	req            *http.Request
	start          time.Time
	resp           *http.Response
	end            time.Time
	captureContent bool
}

func copyReq(req *http.Request) (*http.Request, *http.Request) {
	reqCopy := new(http.Request)
	*reqCopy = *req
	req.Body, reqCopy.Body = copyReadCloser(req.Body, req.ContentLength)
	return req, reqCopy
}

func copyResp(resp *http.Response) (*http.Response, *http.Response) {
	respCopy := new(http.Response)
	*respCopy = *resp
	resp.Body, respCopy.Body = copyReadCloser(resp.Body, resp.ContentLength)
	return resp, respCopy
}

func copyReadCloser(readCloser io.ReadCloser, len int64) (io.ReadCloser, io.ReadCloser) {
	if len < 0 {
		len = 0
	}
	temp := bytes.NewBuffer(make([]byte, 0, len))
	teeReader := io.TeeReader(readCloser, temp)
	copy := bytes.NewBuffer(make([]byte, 0, len))
	copy.ReadFrom(teeReader)
	return ioutil.NopCloser(temp), ioutil.NopCloser(copy)
}

// LogToHARFile collects all the content from the Request/Response
// roundtrip and stores it in memory until you call
// `FlushHARToDisk(filename)`.. at which point it will all be flushed
// to disk in HAR file format.
//
// LogToHARFile alwasy returns `NEXT`.
func (ctx *ProxyCtx) LogToHARFile(captureContent bool) Next {
	return ctx.LogToHAR(captureContent)
}

func (ctx *ProxyCtx) LogToHAR(captureContent bool) Next {
	ctx.proxy.harFlusherRunOnce.Do(func() {
		go ctx.proxy.harLogAggregator()
	})

	ctx.isLogEnabled = true
	ctx.isLogWithContent = captureContent

	return NEXT
}

func (ctx *ProxyCtx) FlushHARToDisk(filename string) {
	ctx.proxy.FlushHARToDisk(filename)
}

func (proxy *ProxyHttpServer) FlushHARMemory() (chan *har.Har){
	proxy.Logf("Calling a flush of HAR to memory")
	harMemory := make(chan *har.Har)

	proxy.harFlushToMemory <- harMemory

	return harMemory
}

func (proxy *ProxyHttpServer) FlushHARToDisk(filename string) {
	proxy.Logf("Calling a flush of HAR to disk")
	proxy.harFlushRequest <- filename
}
