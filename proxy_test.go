package goproxy_test



import (
	//"bufio"
	//"bytes"
	"crypto/tls"
	//"image"
	"io"
	"io/ioutil"
	//"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	//"os/exec"
	"strings"
	"testing"

	"github.com/winstonprivacyinc/goproxy"
	//"github.com/abourget/goproxy/ext/image"
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	//"net/http/httptrace"
	"time"
	"net"
	"bufio"
	"net/textproto"
	//"bytes"
	"github.com/gorilla/websocket"
	"crypto/x509"
)


var acceptAllCerts = &tls.Config{InsecureSkipVerify: true}

//var noProxyClient = &http.Client{Transport: &http.Transport{TLSClientConfig: acceptAllCerts}}

var srvhttps = httptest.NewTLSServer(ConstantHandler("bobo"))
var srv = httptest.NewServer(nil)
//var fs = httptest.NewServer(http.FileServer(http.Dir(".")))




/*
func localFile(url string) string { return fs.URL + "/" + url }
func localTls(url string) string  { return https.URL + url }
*/


func TestConnectReqWithProxy(t *testing.T) {
	// Confirms that we can connect using the normal methods to the destination in the next test.
	Convey("Can make ordinary local TLS connection to Google", t, func() {

		conn, err := net.Dial("tcp", "www.google.com:443")
		So(err, ShouldEqual, nil)

		//tlsConfig := http.DefaultTransport.(*http.Transport).TLSClientConfig
		//(*tlsConfig).InsecureSkipVerify = true

		// Send a request directly to the tunnel.
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
		},)

		timeoutDuration := 10 * time.Second
		conn.SetReadDeadline(time.Now().Add(timeoutDuration))
		conn.SetWriteDeadline(time.Now().Add(timeoutDuration))

		err = tlsConn.Handshake()
		So(err, ShouldEqual, nil)

		//state := tlsConn.ConnectionState()
		//fmt.Println("SSL ServerName : " + state.ServerName)
		//fmt.Println("SSL Handshake : ", state.HandshakeComplete)
		//fmt.Println("SSL Mutual : ", state.NegotiatedProtocolIsMutual)


		request, err := http.NewRequest("GET", "https://www.google.com", nil)
		request.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36")


		//fmt.Println("[TEST] Sending ordinary TLS request.")

		request.Write(tlsConn)

		foundOK := parseResponse(tlsConn)

		So(foundOK, ShouldEqual, true)

		conn.Close()

	})

	Convey("Can perform a CONNECT request to explicitly proxy to another server", t, func() {

		//fmt.Println()
		//fmt.Println("[TEST] Starting CONNECT request via proxy test")
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true

		calledConnectHandler := false
		calledRequestHandler := false
		calledResponseHandler := false
		proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			//fmt.Printf("[TEST] HandleConnectFunc() called\n")
			calledConnectHandler = true
			return goproxy.NEXT
		})

		// Hook the proxy request handler
		proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			calledRequestHandler = true
			//fmt.Printf("[TEST] HandleRequestFunc() - Request function triggered: %s\n", ctx.Req.URL)
			return goproxy.NEXT
		})

		proxy.HandleResponseFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			//fmt.Printf("[TEST] HandleResponseFunc() - Response received: %s\n", ctx.Req.URL)
			calledResponseHandler = true
			return goproxy.NEXT
		})

		_, err := oneShotProxy(proxy, "9006")
		So(err, ShouldEqual, nil)

		// We cannot use our local server because our proxy does not allow forwarding
		// to IP addresses
		conn, err := connectraw("127.0.0.1:9006", "google.com:443")

		So(err, ShouldEqual, nil)
		So(conn, ShouldNotEqual, nil)


		So(calledRequestHandler, ShouldEqual, false)
		So(calledResponseHandler, ShouldEqual, false)
		So(calledConnectHandler, ShouldEqual, true)

		//fmt.Println("[TEST] Tunnelled to destination. Sending TLS request.")
		// Send a request directly to the tunnel.
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
		},)

		timeoutDuration := 10 * time.Second
		conn.SetReadDeadline(time.Now().Add(timeoutDuration))
		conn.SetWriteDeadline(time.Now().Add(timeoutDuration))

		err = tlsConn.Handshake()
		So(err, ShouldEqual, nil)

		request, err := http.NewRequest("GET", "https://www.google.com", nil)
		request.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36")
		request.Write(tlsConn)

		//fmt.Println("[TEST] Sent request. Parsing response.")

		foundOK := parseResponse(tlsConn)
		So(foundOK, ShouldEqual, true)

		conn.Close()
	})
}

func TestHttpGetReqWithProxy(t *testing.T) {
	Convey("Can proxy HTTP request", t, func() {
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true

		calledConnectHandler := false
		calledRequestHandler := false
		calledResponseHandler := false
		proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			//fmt.Printf("[TEST] HandleConnectFunc() called\n")
			calledConnectHandler = true
			return goproxy.NEXT
		})

		// Hook the proxy request handler
		proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			calledRequestHandler = true
			//fmt.Printf("[TEST] HandleRequestFunc() - Request function triggered: %s\n", ctx.Req.URL)
			return goproxy.NEXT
		})

		proxy.HandleResponseFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			//fmt.Printf("[TEST] HandleResponseFunc() - Response received: %s\n", ctx.Req.URL)
			calledResponseHandler = true
			return goproxy.NEXT
		})

		client, err := oneShotProxy(proxy, "9001")
		So(err, ShouldEqual, nil)

		r := string(getOrFail(srv.URL + "/bobo", client, t))
		So(r, ShouldEqual, "bobo")
		So(calledRequestHandler, ShouldEqual, true)
		So(calledResponseHandler, ShouldEqual, false)
		So(calledConnectHandler, ShouldEqual, false)

		calledRequestHandler = false
		r = string(getOrFail(srv.URL + "/bobo", client, t))
		So(r, ShouldEqual, "bobo")

		// The request handler should not be called a second time because the TCP connection was re-used.
		So(calledRequestHandler, ShouldEqual, false)



	})
}

func TestHttpsGetReqWithProxy(t *testing.T) {
	// Confirms that we can connect using the normal methods to the destination in the next test.
	Convey("Can proxy HTTPS request", t, func() {
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true

		calledConnectHandler := false
		calledRequestHandler := false
		calledResponseHandler := false
		proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			//fmt.Printf("[TEST] HandleConnectFunc() called\n")
			calledConnectHandler = true
			return goproxy.NEXT
		})

		// Hook the proxy request handler
		proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			calledRequestHandler = true
			//fmt.Printf("[TEST] HandleRequestFunc() - Request function triggered: %s\n", ctx.Req.URL)
			return goproxy.NEXT
		})

		proxy.HandleResponseFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			//fmt.Printf("[TEST] HandleResponseFunc() - Response received: %s\n", ctx.Req.URL)
			calledResponseHandler = true
			return goproxy.NEXT
		})

		port := "9017"

		_, err := oneShotTLSProxy(proxy, port)
		So(err, ShouldEqual, nil)

		// Run the request without a proxy to make sure it's working
		//fmt.Println("[TEST] Calling HTTPS server without proxy.")
		request, err := http.NewRequest("GET", srvhttps.URL + "/bobo", nil)
		tr := &http.Transport{TLSClientConfig: acceptAllCerts}
		directclient := &http.Client{Transport: tr}

		resp, err := directclient.Do(request)
		So(err, ShouldEqual, nil)
		resptxt, err := ioutil.ReadAll(resp.Body)
		So(err, ShouldEqual, nil)
		So(string(resptxt), ShouldContainSubstring, "bobo")
		resp.Body.Close()
		//fmt.Println("[TEST] Direct HTTPS server request succeeded.")

		// TLS server is working. Open a TLS tunnel to the proxy and send a request for the resource.
		// We can't use the native Golang client for this because it will explicitly proxy the request
		// via CONNECT instead of doing a transparent intercept.

		// Dial proxy directly. This simulates a transparent intercept.
		proxyname := "127.0.0.1:" + port

		//fmt.Println("[TEST] Dialing test server", proxyname)
		conn, err := net.Dial("tcp", proxyname)

		So(err, ShouldEqual, nil)
		So(conn, ShouldNotEqual, nil)

		ix := strings.LastIndex(srvhttps.URL, ":")
		serverport := srvhttps.URL[ix+1:]
		servername := "127.0.0.1:" + serverport


		// Handshake - the server name determines the destination
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName: servername,
		})

		//timeoutDuration := 10 * time.Second
		//conn.SetReadDeadline(time.Now().Add(timeoutDuration))
		//conn.SetWriteDeadline(time.Now().Add(timeoutDuration))

		//fmt.Println("[TEST] Starting TLS handshake")
		err = tlsConn.Handshake()
		So(err, ShouldEqual, nil)


		//now := time.Now()

		// Send request to original website
		request, err = http.NewRequest("GET", srvhttps.URL + "/bobo", nil)
		request.Write(tlsConn)

		// Read response
		body := parseResponseBody(tlsConn)

		//fmt.Println("[TEST] Elapsed time for response", time.Since(now))

		So(body, ShouldContainSubstring, "bobo")
		So(calledConnectHandler, ShouldEqual, true)
		So(calledRequestHandler, ShouldEqual, false)
		So(calledResponseHandler, ShouldEqual, false)

	})

}

func TestErrorWithProxy(t *testing.T) {
	Convey("Goproxy returns an error page when a request is rejected.", t, func() {
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true

		calledConnectHandler := false
		calledRequestHandler := false
		calledResponseHandler := false
		proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			//fmt.Printf("[TEST] HandleConnectFunc() called\n")
			calledConnectHandler = true
			return goproxy.NEXT
		})

		// Hook the proxy request handler
		proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			calledRequestHandler = true
			//fmt.Printf("[TEST] HandleRequestFunc() - Request function triggered: %s\n", ctx.Req.URL)
			return goproxy.REJECT
		})

		proxy.HandleResponseFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			//fmt.Printf("[TEST] HandleResponseFunc() - Response received: %s\n", ctx.Req.URL)
			calledResponseHandler = true
			return goproxy.NEXT
		})

		client, err := oneShotProxy(proxy, "9002")
		So(err, ShouldEqual, nil)

		r := string(getOrFail(srv.URL + "/bobo", client, t))
		//fmt.Printf("[TEST] getOrFail returned body:\n%s\n", r)
		So(r, ShouldContainSubstring, "blocked by Winston")
		So(calledRequestHandler, ShouldEqual, true)
		So(calledResponseHandler, ShouldEqual, false)
		So(calledConnectHandler, ShouldEqual, false)
	})
}

func TestMissingHostHeader(t *testing.T) {
	Convey("Goproxy does not add a host header if it wasn't provided.", t, func() {
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true

		calledConnectHandler := false
		calledRequestHandler := false
		proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			//fmt.Printf("[TEST] HandleConnectFunc() called\n")
			calledConnectHandler = true
			return goproxy.NEXT
		})

		// Hook the proxy request handler
		proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			calledRequestHandler = true
			fmt.Printf("[TEST] HandleRequestFunc() - Original Request: \n%s\n", string(ctx.NonHTTPRequest))
			return goproxy.NEXT
		})

		//client
		_, err := oneShotProxy(proxy, "9004")
		So(err, ShouldEqual, nil)

		//fmt.Println("[TEST] Starting low level HTTP request")
		// Send the next request directly on the wire to avoid adding a host header.
		b, err := getraw("127.0.0.1:9004", srv.URL + "/header?header=Host", "User-Agent: None\r\n")

		So(err, ShouldEqual, nil)
		body := string(b)
		So(len(b), ShouldNotEqual, 0)
		So(body, ShouldNotContainSubstring, "Host")
		So(body, ShouldContainSubstring, "Content-Length")

		So(calledRequestHandler, ShouldEqual, true)
		calledRequestHandler = false

		// Send the request again but get the user agent back
		b, err = getraw("127.0.0.1:9004", srv.URL + "/header?header=User-Agent", "User-Agent: None\r\n")
		fmt.Printf("[TEST] Server's HTTP response was\n%s\n", string(b))
		body = string(b)
		So(len(b), ShouldNotEqual, 0)
		So(body, ShouldNotContainSubstring, "Host")
		So(body, ShouldContainSubstring, "None")

		So(calledRequestHandler, ShouldEqual, true)
		So(calledConnectHandler, ShouldEqual, false)
	})
}

func TestWebsockets(t *testing.T) {
	Convey("Test HTTP websocket functionality", t, func() {
		// Create test server with the echo handler.
		listener := make(chan string, 100)
		lastmsg := ""
		msgcount := 0
		go func() {
			for {
				msg := <-listener
				lastmsg = msg
				msgcount++
				//fmt.Println("Test websocket server received message", msg)
			}
		}()

		loggedecho := func(w http.ResponseWriter, r *http.Request) {
			echo(w, r, listener)
		}

		s := httptest.NewServer(http.HandlerFunc(loggedecho))
		defer s.Close()

		fmt.Println()
		fmt.Println("Starting HTTP websocket test")
		fmt.Println()

		// Convert http://127.0.0.1 to ws://127.0.0.1
		u := "ws" + strings.TrimPrefix(s.URL, "http")

		fmt.Printf("server listening on %+v\n", u)

		// Connect to the server
		ws, _, err := websocket.DefaultDialer.Dial(u, nil)
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer ws.Close()

		// Send message to server, read response and check to see if it's what we expect.
		for i := 0; i < 10; i++ {
			err := ws.WriteMessage(websocket.TextMessage, []byte("hello"))
			So(err, ShouldEqual, nil)

			_, p, err := ws.ReadMessage()
			So(err, ShouldEqual, nil)
			So(string(p), ShouldEqual, "hello")
		}



		// The websockets server is working. Set up a local proxy and connect to it indirectly.
		// Start a local proxy
		//goproxy.LoadDefaultConfig()
		proxy := goproxy.NewProxyHttpServer()
		So(proxy, ShouldNotEqual, nil)

		calledConnectHandler := false
		calledRequestHandler := false
		calledResponseHandler := false

		// FIX: In production, ws:// requests should not go through the connect handler
		// because this will route it to ForwardConnect(), dropping the original websocket
		// headers.
		proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			fmt.Printf("[TEST] HandleConnectFunc() called\n")
			ctx.PrivateNetwork = false
			calledConnectHandler = true
			return goproxy.FORWARD
		})

		// Hook the proxy request handler
		proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			calledRequestHandler = true
			fmt.Printf("[TEST] HandleRequestFunc() - Request function triggered: %s  session:%d\n", ctx.Req.URL, ctx.Session)
			ctx.PrivateNetwork = false
			return goproxy.FORWARD
		})

		proxy.HandleResponseFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			fmt.Printf("[TEST] HandleResponseFunc() - Response received: %s  session:%d\n", ctx.Req.URL, ctx.Session)
			calledResponseHandler = true
			return goproxy.NEXT
		})

		// Start the proxy listener
		proxyport := "127.0.0.1:9133"
		go proxy.ListenAndServe(proxyport)

		// Wait a little bit for the network to start up
		time.Sleep(1 * time.Second)

		fmt.Println("[TEST] Proxy server started", proxyport)

		// Repeat the websockets test queries using a proxy
		d := websocket.Dialer{
			NetDial: func(network, addr string) (net.Conn, error) {
				return net.Dial("tcp", proxyport)
			},
			// Note: don't use this because it's an explicit proxy. We don't support this.
			//Proxy: http.ProxyURL(&url.URL{
			//	Scheme: "http", // or "https" depending on your proxy
			//	Host: proxyport ,
			//	Path: "/",
			//}),
		}

		wsproxy, _, err := d.Dial(u, nil)
		So(err, ShouldEqual, nil)
		defer wsproxy.Close()

		So(calledConnectHandler, ShouldEqual, false)
		So(calledResponseHandler, ShouldEqual, false)
		So(calledRequestHandler, ShouldEqual, true)

		msgcount = 0
		lastmsg = ""

		// Send message to server, read response and check to see if it's what we expect.
		for i := 0; i < 10; i++ {
			err := wsproxy.WriteMessage(websocket.TextMessage, []byte("realhello"))
			So(err, ShouldEqual, nil)

			_, p, err := wsproxy.ReadMessage()
			So(err, ShouldEqual, nil)
			So(string(p), ShouldEqual, "realhello")
		}

		So(msgcount, ShouldEqual, 10)
		So(lastmsg, ShouldEqual, "realhello")
		fmt.Println("[TEST] Finished HTTP websocket test")

	})

	Convey("Test HTTPS websocket functionality", t, func() {
		fmt.Println()
		fmt.Println("Starting HTTPS websocket test")
		fmt.Println()

		// Create test server with the echo handler.
		listener := make(chan string, 100)
		lastmsg := ""
		msgcount := 0
		go func() {
			for {
				msg := <-listener
				lastmsg = msg
				msgcount++
				//fmt.Println("Test websocket server received message", msg)
			}
		}()

		loggedecho := func(w http.ResponseWriter, r *http.Request) {
			echo(w, r, listener)
		}

		s := httptest.NewTLSServer(http.HandlerFunc(loggedecho))
		defer s.Close()

		cert, err := x509.ParseCertificate(s.TLS.Certificates[0].Certificate[0])
		So(err, ShouldEqual, nil)

		certpool := x509.NewCertPool()
		certpool.AddCert(cert)

		// Convert http://127.0.0.1 to ws://127.0.0.1
		u := "wss" + strings.TrimPrefix(s.URL, "https")

		fmt.Printf("server listening on %+v\n", u)

		// Connect to the server. We don't care about verifying a certificate.
		cstDialer := websocket.DefaultDialer
		cstDialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		ws, _, err := cstDialer.Dial(u, nil)
		if err != nil {
			t.Fatalf("%v", err)
		}
		defer ws.Close()

		// Send message to server, read response and check to see if it's what we expect.
		for i := 0; i < 10; i++ {
			err := ws.WriteMessage(websocket.TextMessage, []byte("hello"))
			So(err, ShouldEqual, nil)

			_, p, err := ws.ReadMessage()
			So(err, ShouldEqual, nil)
			So(string(p), ShouldEqual, "hello")
		}

		fmt.Println("[TEST] TLS websockets server is working.")

		// The websockets server is working. Set up a local proxy and connect to it indirectly.
		// Start a local proxy
		//goproxy.LoadDefaultConfig()
		proxy := goproxy.NewProxyHttpServer()
		So(proxy, ShouldNotEqual, nil)

		calledConnectHandler := false
		calledRequestHandler := false
		calledResponseHandler := false

		proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			fmt.Printf("[TEST] HandleConnectFunc() called\n")
			calledConnectHandler = true
			return goproxy.FORWARD
		})

		// Hook the proxy request handler
		proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			calledRequestHandler = true
			fmt.Printf("[TEST] HandleRequestFunc() - Request function triggered: %s  session:%d\n", ctx.Req.URL, ctx.Session)

			// Force all requests to go through the private network.
			ctx.PrivateNetwork = false
			return goproxy.FORWARD
		})

		proxy.HandleResponseFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			fmt.Printf("[TEST] HandleResponseFunc() - Response received: %s  session:%d\n", ctx.Req.URL, ctx.Session)

			// This should never be hit with a non-http protocol
			calledResponseHandler = true
			return goproxy.NEXT
		})

		// Start the proxy listener
		proxyport := "127.0.0.1:9104"
		go proxy.ListenAndServeTLS(proxyport)

		// Wait a little bit for the network to start up
		time.Sleep(1 * time.Second)

		fmt.Println("[TEST] TLS Proxy server started", proxyport)


		// Repeat the websockets test queries using a proxy
		// Note: We have to send in the server name explicitly so that the proxy server can route it to the right place.
		// This simulates a transparent intercept. If we don't do this, it will re-route it to 127.0.0.1:443.
		ix := strings.LastIndex(s.URL, ":")
		serverport := s.URL[ix+1:]
		servername := "127.0.0.1:" + serverport

		fmt.Println("[TEST] Simulating transparent intercept to", u, "->", servername)
		d := websocket.Dialer{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: servername},	// , RootCAs: certpool
			NetDial: func(network, addr string) (net.Conn, error) {
				return net.Dial("tcp", proxyport)
			},
			// Note: don't use this because it's an explicit proxy. We don't support this.
			//Proxy: http.ProxyURL(&url.URL{
			//	Scheme: "http", // or "https" depending on your proxy
			//	Host: proxyport ,
			//	Path: "/",
			//}),
		}

		wsproxy, _, err := d.Dial(u, nil)
		So(err, ShouldEqual, nil)
		defer wsproxy.Close()

		// TLS connections always go through the Connect handler now. The connection is encrypted
		// so it's not possible for the Request handler to do anything with it.
		So(calledConnectHandler, ShouldEqual, true)
		So(calledResponseHandler, ShouldEqual, false)
		So(calledRequestHandler, ShouldEqual, false)

		msgcount = 0
		lastmsg = ""

		// Send message to server, read response and check to see if it's what we expect.
		for i := 0; i < 10; i++ {
			err := wsproxy.WriteMessage(websocket.TextMessage, []byte("realhello"))
			So(err, ShouldEqual, nil)

			_, p, err := wsproxy.ReadMessage()
			So(err, ShouldEqual, nil)
			So(string(p), ShouldEqual, "realhello")
		}

		So(msgcount, ShouldEqual, 10)
		So(lastmsg, ShouldEqual, "realhello")
		fmt.Println("[TEST] Finished HTTP websocket test")

	})
}

// FIX WINSTON-883 - Blink cameras send a bad SNI field in the CLIENTHELLO message (*.domain.com).
// This ensures that Goproxy fails over to the conntrak destination resolver routine if it can't parse
// a valid hostname.
func TestHttpsBadSNI(t *testing.T) {
	// Confirms that we can connect using the normal methods to the destination in the next test.
	Convey("Correctly routes HTTPS requests with bad SNI field", t, func() {
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true

		calledConnectHandler := false
		calledRequestHandler := false
		proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			fmt.Printf("[TEST] HandleConnectFunc() called\n")
			calledConnectHandler = true
			return goproxy.NEXT
		})

		// Hook the proxy request handler
		proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			calledRequestHandler = true
			fmt.Printf("[TEST] HandleRequestFunc() - Request function triggered: %s\n", ctx.Req.URL)
			return goproxy.NEXT
		})

		// Hijack the destination resolver because we don't have access to conntrak
		// within the scope of unit tests.
		ix := strings.LastIndex(srvhttps.URL, ":")
		serverport := srvhttps.URL[ix+1:]
		servername := "127.0.0.1:" + serverport
		proxy.DestinationResolver = func(c net.Conn) (string) {
			return servername
		}

		port := "9217"

		_, err := oneShotTLSProxy(proxy, port)
		So(err, ShouldEqual, nil)

		// Run the request with a bad SNI field
		//fmt.Println("[TEST] Calling HTTPS server without proxy.")
		// Dial proxy directly. This simulates a transparent intercept.
		proxyname := "127.0.0.1:" + port

		//fmt.Println("[TEST] Dialing test server", proxyname)
		conn, err := net.Dial("tcp", proxyname)

		So(err, ShouldEqual, nil)
		So(conn, ShouldNotEqual, nil)

		// Bad SNI field sent in. This doesn't point to anything valid.
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName: "*.badsni.com",
		})

		//fmt.Println("[TEST] Starting TLS handshake")
		err = tlsConn.Handshake()
		So(err, ShouldEqual, nil)


		//now := time.Now()

		// Send request to original website
		request, err := http.NewRequest("GET", srvhttps.URL + "/bobo", nil)
		request.Write(tlsConn)

		// Read response
		body := parseResponseBody(tlsConn)

		//fmt.Println("[TEST] Elapsed time for response", time.Since(now))

		So(body, ShouldContainSubstring, "bobo")
		So(calledConnectHandler, ShouldEqual, true)
		So(calledRequestHandler, ShouldEqual, false)

		//fmt.Println("[TEST] Direct HTTPS server request succeeded.")


	})

}

// Confirms that the API can listen and respond to requests
func TestAPIHook(t *testing.T) {
	Convey("Requests can be intercepted by a custom handler", t, func() {
		proxy := goproxy.NewProxyHttpServer()
		proxy.Verbose = true

		calledConnectHandler := false
		calledRequestHandler := false
		calledResponseHandler := false
		proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			//fmt.Printf("[TEST] HandleConnectFunc() called\n")
			calledConnectHandler = true
			return goproxy.NEXT
		})

		// Hook the proxy request handler
		proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			calledRequestHandler = true
			//fmt.Printf("[TEST] HandleRequestFunc() - Request function triggered: %s\n", ctx.Req.URL)
			return goproxy.NEXT
		})

		proxy.HandleResponseFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
			//fmt.Printf("[TEST] HandleResponseFunc() - Response received: %s\n", ctx.Req.URL)
			calledResponseHandler = true
			return goproxy.NEXT
		})

		client, err := oneShotProxy(proxy, "11301")
		So(err, ShouldEqual, nil)

		r := string(getOrFail(srv.URL + "/bobo", client, t))
		So(r, ShouldEqual, "bobo")
		So(calledRequestHandler, ShouldEqual, true)
		So(calledResponseHandler, ShouldEqual, false)
		So(calledConnectHandler, ShouldEqual, false)

		calledRequestHandler = false
		r = string(getOrFail(srv.URL + "/bobo", client, t))
		So(r, ShouldEqual, "bobo")

		// The request handler should not be called a second time because the TCP connection was re-used.
		So(calledRequestHandler, ShouldEqual, false)



	})
}

var upgrader = websocket.Upgrader{}

// Caller should send a listener to eavesdrop on requests
func echo(w http.ResponseWriter, r *http.Request, listener chan string) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
	for {
		mt, message, err := c.ReadMessage()
		listener <- string(message)
		if err != nil {
			break
		}
		err = c.WriteMessage(mt, message)
		if err != nil {
			break
		}
	}
}




/*

func TestSimpleConditionalHook(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()

	mangleRequestPath := goproxy.HandlerFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		ctx.Req.URL.Path = "/bobo"
		return goproxy.NEXT
	})
	proxy.HandleRequest(goproxy.RemoteAddrIs("127.0.0.1")(mangleRequestPath))
	client, l := oneShotProxy(proxy, t)
	defer l.Close()

	if result := string(getOrFail(srv.URL+("/momo"), client, t)); result != "bobo" {
		t.Error("Redirecting all requests from 127.0.0.1 to bobo, didn't work." +
			" (Might break if Go's client sets RemoteAddr to IPv6 address). Got: " +
			result)
	}
}

func TestAlwaysHook(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		ctx.Req.URL.Path = "/bobo"
		return goproxy.NEXT
	})
	client, l := oneShotProxy(proxy, t)
	defer l.Close()

	if result := string(getOrFail(srv.URL+("/momo"), client, t)); result != "bobo" {
		t.Error("Redirecting all requests from 127.0.0.1 to bobo, didn't work." +
			" (Might break if Go's client sets RemoteAddr to IPv6 address). Got: " +
			result)
	}
}

func TestReplaceReponseForUrl(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.HandleResponse(goproxy.UrlIsIn("/koko")(goproxy.HandlerFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		if ctx.Resp == nil {
			return goproxy.NEXT
		}
		ctx.Resp.StatusCode = http.StatusOK
		ctx.SetResponseBody([]byte("chico"))

		return goproxy.NEXT
	})))

	client, l := oneShotProxy(proxy, t)
	defer l.Close()

	if result := string(getOrFail(srv.URL+("/koko"), client, t)); result != "chico" {
		t.Error("hooked 'koko', should be chico, instead:", result)
	}
	if result := string(getOrFail(srv.URL+("/bobo"), client, t)); result != "bobo" {
		t.Error("still, bobo should stay as usual, instead:", result)
	}
}

func TestOneShotFileServer(t *testing.T) {
	client, l := oneShotProxy(goproxy.NewProxyHttpServer(), t)
	defer l.Close()

	file := "test_data/panda.png"
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal("Cannot find", file)
	}
	if resp, err := client.Get(fs.URL + "/" + file); err == nil {
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatal("got", string(b))
		}
		if int64(len(b)) != info.Size() {
			t.Error("Expected Length", file, info.Size(), "actually", len(b), "starts", string(b[:10]))
		}
	} else {
		t.Fatal("Cannot read from fs server", err)
	}
}

func TestContentType(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()

	mangleImage := goproxy.HandlerFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		ctx.Resp.Header.Set("X-Shmoopi", "1")
		return goproxy.NEXT
	})
	proxy.HandleResponse(goproxy.RespContentTypeIs("image/png")(mangleImage))

	client, l := oneShotProxy(proxy, t)
	defer l.Close()

	for _, file := range []string{"test_data/panda.png", "test_data/football.png"} {
		if resp, err := client.Get(localFile(file)); err != nil || resp.Header.Get("X-Shmoopi") != "1" {
			if err == nil {
				t.Error("pngs should have X-Shmoopi header = 1, actually", resp.Header.Get("X-Shmoopi"))
			} else {
				t.Error("error reading png", err)
			}
		}
	}

	file := "baby.jpg"
	if resp, err := client.Get(localFile(file)); err != nil || resp.Header.Get("X-Shmoopi") != "" {
		if err == nil {
			t.Error("Non png images should NOT have X-Shmoopi header at all", resp.Header.Get("X-Shmoopi"))
		} else {
			t.Error("error reading png", err)
		}
	}
}

func getImage(file string, t *testing.T) image.Image {
	newimage, err := ioutil.ReadFile(file)
	if err != nil {
		t.Fatal("Cannot read file", file, err)
	}
	img, _, err := image.Decode(bytes.NewReader(newimage))
	if err != nil {
		t.Fatal("Cannot decode image", file, err)
	}
	return img
}

func readAll(r io.Reader, t *testing.T) []byte {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal("Cannot read", err)
	}
	return b
}
func readFile(file string, t *testing.T) []byte {
	b, err := ioutil.ReadFile(file)
	if err != nil {
		t.Fatal("Cannot read", err)
	}
	return b
}

func compareImage(eImg, aImg image.Image, t *testing.T) {
	if eImg.Bounds().Dx() != aImg.Bounds().Dx() || eImg.Bounds().Dy() != aImg.Bounds().Dy() {
		t.Error("image sizes different")
		return
	}
	for i := 0; i < eImg.Bounds().Dx(); i++ {
		for j := 0; j < eImg.Bounds().Dy(); j++ {
			er, eg, eb, ea := eImg.At(i, j).RGBA()
			ar, ag, ab, aa := aImg.At(i, j).RGBA()
			if er != ar || eg != ag || eb != ab || ea != aa {
				t.Error("images different at", i, j, "vals\n", er, eg, eb, ea, "\n", ar, ag, ab, aa, aa)
				return
			}
		}
	}
}

*/
/*
func TestImageHandler(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	football := getImage("test_data/football.png", t)

	proxy.HandleResponse(goproxy.UrlIsIn("/test_data/panda.png")(goproxy_image.HandleImage(func(img image.Image, ctx *goproxy.ProxyCtx) image.Image {
		return football
	})))

	client, l := oneShotProxy(proxy, t)
	defer l.Close()

	resp, err := client.Get(localFile("test_data/panda.png"))
	if err != nil {
		t.Fatal("Cannot get panda.png", err)
	}

	img, _, err := image.Decode(resp.Body)
	if err != nil {
		t.Error("decode", err)
	} else {
		compareImage(football, img, t)
	}

	// and again
	resp, err = client.Get(localFile("test_data/panda.png"))
	if err != nil {
		t.Fatal("Cannot get panda.png", err)
	}

	img, _, err = image.Decode(resp.Body)
	if err != nil {
		t.Error("decode", err)
	} else {
		compareImage(football, img, t)
	}
}
*//*


func TestChangeResp(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.HandleResponseFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		ctx.Resp.Body.Read([]byte{0})
		ctx.Resp.Body = ioutil.NopCloser(new(bytes.Buffer))
		return goproxy.NEXT
	})

	client, l := oneShotProxy(proxy, t)
	defer l.Close()

	resp, err := client.Get(localFile("test_data/panda.png"))
	if err != nil {
		t.Fatal(err)
	}
	ioutil.ReadAll(resp.Body)
	_, err = client.Get(localFile("/bobo"))
	if err != nil {
		t.Fatal(err)
	}
}
*/
/*
func TestReplaceImage(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()

	panda := getImage("test_data/panda.png", t)
	football := getImage("test_data/football.png", t)

	proxy.HandleResponse(goproxy.UrlIsIn("/test_data/panda.png")(goproxy_image.HandleImage(func(img image.Image, ctx *goproxy.ProxyCtx) image.Image {
		return football
	})))

	proxy.HandleResponse(goproxy.UrlIsIn("/test_data/football.png")(goproxy_image.HandleImage(func(img image.Image, ctx *goproxy.ProxyCtx) image.Image {
		return panda
	})))

	client, l := oneShotProxy(proxy, t)
	defer l.Close()

	imgByPandaReq, _, err := image.Decode(bytes.NewReader(getOrFail(localFile("test_data/panda.png"), client, t)))
	fatalOnErr(err, "decode panda", t)
	compareImage(football, imgByPandaReq, t)

	imgByFootballReq, _, err := image.Decode(bytes.NewReader(getOrFail(localFile("test_data/football.png"), client, t)))
	fatalOnErr(err, "decode football", t)
	compareImage(panda, imgByFootballReq, t)
}
*//*


func getCert(c *tls.Conn, t *testing.T) []byte {
	if err := c.Handshake(); err != nil {
		t.Fatal("cannot handshake", err)
	}
	return c.ConnectionState().PeerCertificates[0].Raw
}

// TODO: Test needs to be refactored because our certificate routine attempts to get the original TLS certificate, which doesn't exist
*/
/*
func TestSimpleMitmWithSNI(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		ctx.SNIHost()
		return goproxy.MITM
	})

	client, l := oneShotProxy(proxy, t)
	defer l.Close()

	if resp := string(getOrFail(https.URL+"/bobo", client, t)); resp != "bobo" {
		t.Error("Wrong response when mitm", resp, "expected bobo")
	}
	if resp := string(getOrFail(https.URL+"/query?result=bar", client, t)); resp != "bar" {
		t.Error("Wrong response when mitm", resp, "expected bar")
	}
}
*//*


// TODO: Test needs to be refactored because our certificate routine attempts to get the original TLS certificate, which doesn't exist
*/
/*
func TestSimpleMitmWithoutSNI(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		return goproxy.MITM
	})

	client, l := oneShotProxy(proxy, t)
	defer l.Close()

	if resp := string(getOrFail(https.URL+"/bobo", client, t)); resp != "bobo" {
		t.Error("Wrong response when mitm", resp, "expected bobo")
	}
	if resp := string(getOrFail(https.URL+"/query?result=bar", client, t)); resp != "bar" {
		t.Error("Wrong response when mitm", resp, "expected bar")
	}
}
*//*


// TODO: Test needs to be refactored because our certificate routine attempts to get the original TLS certificate, which doesn't exist
*/
/*
func TestMitmDynamicCertificate(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.HandleConnect(goproxy.AlwaysMitm)

	_, l := oneShotProxy(proxy, t)
	defer l.Close()

	c, err := tls.Dial("tcp", https.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal("cannot dial to tcp server", err)
	}
	origCert := getCert(c, t)
	c.Close()

	c2, err := net.Dial("tcp", l.Listener.Addr().String())
	if err != nil {
		t.Fatal("dialing to proxy", err)
	}
	creq, err := http.NewRequest("CONNECT", https.URL, nil)
	//creq,err := http.NewRequest("CONNECT","https://google.com:443",nil)
	if err != nil {
		t.Fatal("create new request", creq)
	}
	creq.Write(c2)
	c2buf := bufio.NewReader(c2)
	resp, err := http.ReadResponse(c2buf, creq)
	if err != nil || resp.StatusCode != 200 {
		t.Fatal("Cannot CONNECT through proxy", err)
	}
	c2tls := tls.Client(c2, &tls.Config{InsecureSkipVerify: true})
	proxyCert := getCert(c2tls, t)

	if bytes.Equal(proxyCert, origCert) {
		t.Errorf("Certificate after mitm is not different\n%v\n%v",
			base64.StdEncoding.EncodeToString(origCert),
			base64.StdEncoding.EncodeToString(proxyCert))
	}
}
*//*


func TestConnectHandler(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	althttps := httptest.NewTLSServer(ConstantHandler("althttps"))
	proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		u, _ := url.Parse(althttps.URL)
		ctx.SetDestinationHost(u.Host)
		return goproxy.FORWARD
	})

	client, l := oneShotProxy(proxy, t)
	defer l.Close()
	if resp := string(getOrFail(https.URL+"/alturl", client, t)); resp != "althttps" {
		t.Error("Proxy should redirect CONNECT requests to local althttps server, expected 'althttps' got ", resp)
	}
}

// TODO: Refactor
*/
/*func TestMitmIsFiltered(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	//proxy.Verbose = true
	proxy.HandleConnect(goproxy.AlwaysMitm)
	// PREVIOUSLY: proxy.OnRequest(goproxy.ReqHostIs(https.Listener.Addr().String())).HandleConnect(goproxy.AlwaysMitm)
	proxy.HandleRequest(goproxy.UrlIsIn("/momo")(goproxy.HandlerFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		ctx.NewTextResponse("koko")
		return goproxy.FORWARD
	})))

	client, l := oneShotProxy(proxy, t)
	defer l.Close()

	if resp := string(getOrFail(https.URL+"/momo", client, t)); resp != "koko" {
		t.Error("Proxy should capture /momo to be koko and not", resp)
	}

	if resp := string(getOrFail(https.URL+"/bobo", client, t)); resp != "bobo" {
		t.Error("But still /bobo should be 'bobo' and not", resp)
	}
}*//*


func TestFirstHandlerMatches(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		ctx.NewTextResponse("koko")
		return goproxy.FORWARD
	})
	proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		panic("should never get here, because of the previous FORWARD")
	})

	client, l := oneShotProxy(proxy, t)
	defer l.Close()

	if resp := string(getOrFail(srv.URL+"/", client, t)); resp != "koko" {
		t.Error("should return always koko and not", resp)
	}
}

func constantHttpServer(content []byte) (addr string) {
	l, err := net.Listen("tcp", "localhost:0")
	panicOnErr(err, "listen")
	go func() {
		c, err := l.Accept()
		panicOnErr(err, "accept")
		buf := bufio.NewReader(c)
		_, err = http.ReadRequest(buf)
		panicOnErr(err, "readReq")
		c.Write(content)
		c.Close()
		l.Close()
	}()
	return l.Addr().String()
}

func TestIcyResponse(t *testing.T) {
	// TODO: fix this test
	return // skip for now
	s := constantHttpServer([]byte("ICY 200 OK\r\n\r\nblablabla"))
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	_, l := oneShotProxy(proxy, t)
	defer l.Close()
	req, err := http.NewRequest("GET", "http://"+s, nil)
	panicOnErr(err, "newReq")
	proxyip := l.URL[len("http://"):]
	println("got ip: " + proxyip)
	c, err := net.Dial("tcp", proxyip)
	panicOnErr(err, "dial")
	defer c.Close()
	req.WriteProxy(c)
	raw, err := ioutil.ReadAll(c)
	panicOnErr(err, "readAll")
	if string(raw) != "ICY 200 OK\r\n\r\nblablabla" {
		t.Error("Proxy did not send the malformed response received")
	}
}

type VerifyNoProxyHeaders struct {
	*testing.T
}

func (v VerifyNoProxyHeaders) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Connection") != "" || r.Header.Get("Proxy-Connection") != "" {
		v.Error("Got Connection header from goproxy", r.Header)
	}
}

// TODO: Refactor
*/
/*
func TestNoProxyHeaders(t *testing.T) {
	s := httptest.NewServer(VerifyNoProxyHeaders{t})
	client, l := oneShotProxy(goproxy.NewProxyHttpServer(), t)
	defer l.Close()
	req, err := http.NewRequest("GET", s.URL, nil)
	panicOnErr(err, "bad request")
	req.Header.Add("Connection", "close")
	req.Header.Add("Proxy-Connection", "close")
	client.Do(req)
}
*//*


func TestNoProxyHeadersHttps(t *testing.T) {
	s := httptest.NewTLSServer(VerifyNoProxyHeaders{t})
	proxy := goproxy.NewProxyHttpServer()
	proxy.HandleConnect(goproxy.AlwaysMitm)
	client, l := oneShotProxy(proxy, t)
	defer l.Close()
	req, err := http.NewRequest("GET", s.URL, nil)
	panicOnErr(err, "bad request")
	req.Header.Add("Connection", "close")
	req.Header.Add("Proxy-Connection", "close")
	client.Do(req)
}

func TestHeadReqHasContentLength(t *testing.T) {
	client, l := oneShotProxy(goproxy.NewProxyHttpServer(), t)
	defer l.Close()

	resp, err := client.Head(localFile("test_data/panda.png"))
	panicOnErr(err, "resp to HEAD")
	if resp.Header.Get("Content-Length") == "" {
		t.Error("Content-Length should exist on HEAD requests")
	}
}

// TODO: REFACTOR
*/
/*func TestChunkedResponse(t *testing.T) {
	l, err := net.Listen("tcp", ":10234")
	panicOnErr(err, "listen")
	defer l.Close()
	go func() {
		for i := 0; i < 2; i++ {
			c, err := l.Accept()
			panicOnErr(err, "accept")
			_, err = http.ReadRequest(bufio.NewReader(c))
			panicOnErr(err, "readrequest")
			io.WriteString(c, "HTTP/1.1 200 OK\r\n"+
				"Content-Type: text/plain\r\n"+
				"Transfer-Encoding: chunked\r\n\r\n"+
				"25\r\n"+
				"This is the data in the first chunk\r\n\r\n"+
				"1C\r\n"+
				"and this is the second one\r\n\r\n"+
				"3\r\n"+
				"con\r\n"+
				"8\r\n"+
				"sequence\r\n0\r\n\r\n")
			c.Close()
		}
	}()

	c, err := net.Dial("tcp", "localhost:10234")
	panicOnErr(err, "dial")
	defer c.Close()
	req, _ := http.NewRequest("GET", "/", nil)
	req.Write(c)
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	panicOnErr(err, "readresp")
	b, err := ioutil.ReadAll(resp.Body)
	panicOnErr(err, "readall")
	expected := "This is the data in the first chunk\r\nand this is the second one\r\nconsequence"
	if string(b) != expected {
		t.Errorf("Got `%v` expected `%v`", string(b), expected)
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.HandleResponseFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		resp := ctx.Resp
		panicOnErr(ctx.Error, "error reading output")
		b, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		panicOnErr(err, "readall onresp")
		if enc := resp.Header.Get("Transfer-Encoding"); enc != "" {
			t.Fatal("Chunked response should be received as plaintext", enc)
		}
		resp.Body = ioutil.NopCloser(bytes.NewBufferString(strings.Replace(string(b), "e", "E", -1)))
		return goproxy.NEXT
	})

	client, s := oneShotProxy(proxy, t)
	defer s.Close()

	resp, err = client.Get("http://localhost:10234/")
	panicOnErr(err, "client.Get")
	b, err = ioutil.ReadAll(resp.Body)
	panicOnErr(err, "readall proxy")
	if string(b) != strings.Replace(expected, "e", "E", -1) {
		t.Error("expected", expected, "w/ e->E. Got", string(b))
	}
}*//*


// TODO: REFACTOR
*/
/*
func TestGoproxyThroughProxy(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	proxy2 := goproxy.NewProxyHttpServer()
	doubleString := goproxy.HandlerFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		resp := ctx.Resp
		b, err := ioutil.ReadAll(resp.Body)
		panicOnErr(err, "readAll resp")
		resp.Body = ioutil.NopCloser(bytes.NewBufferString(string(b) + " " + string(b)))
		return goproxy.NEXT
	})
	proxy.HandleConnect(goproxy.AlwaysMitm)
	proxy.HandleResponse(doubleString)

	_, l := oneShotProxy(proxy, t)
	defer l.Close()

	proxy2.ConnectDial = proxy2.NewConnectDialToProxy(l.URL)

	client, l2 := oneShotProxy(proxy2, t)
	defer l2.Close()
	if r := string(getOrFail(https.URL+"/bobo", client, t)); r != "bobo bobo" {
		t.Error("Expected bobo doubled twice, got", r)
	}

}
*//*


// TODO: Refactor
*/
/*func TestGoproxyHijackConnect(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()

	hijackHandler := goproxy.HandlerFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		req := ctx.Req

		client := ctx.HijackConnect()

		t.Logf("URL %+#v\nSTR %s", req.URL, req.URL.String())
		resp, err := http.Get("http:" + req.URL.String() + "/bobo")
		panicOnErr(err, "http.Get(CONNECT url)")
		panicOnErr(resp.Write(client), "resp.Write(client)")
		resp.Body.Close()
		client.Close()

		return goproxy.DONE
	})
	proxy.HandleRequest(goproxy.RequestHostIsIn(srv.Listener.Addr().String())(hijackHandler))

	client, l := oneShotProxy(proxy, t)
	defer l.Close()
	proxyAddr := l.Listener.Addr().String()
	conn, err := net.Dial("tcp", proxyAddr)
	panicOnErr(err, "conn "+proxyAddr)
	buf := bufio.NewReader(conn)
	writeConnect(conn)
	readConnectResponse(buf)
	if txt := readResponse(buf); txt != "bobo" {
		t.Error("Expected bobo for CONNECT /foo, got", txt)
	}

	if r := string(getOrFail(https.URL+"/bobo", client, t)); r != "bobo" {
		t.Error("Expected bobo would keep working with CONNECT", r)
	}
}*//*


func readResponse(buf *bufio.Reader) string {
	req, err := http.NewRequest("GET", srv.URL, nil)
	panicOnErr(err, "NewRequest")
	resp, err := http.ReadResponse(buf, req)
	panicOnErr(err, "resp.Read")
	defer resp.Body.Close()
	txt, err := ioutil.ReadAll(resp.Body)
	panicOnErr(err, "resp.Read")
	return string(txt)
}

func writeConnect(w io.Writer) {
	req, err := http.NewRequest("CONNECT", srv.URL[len("http://"):], nil)
	panicOnErr(err, "NewRequest")
	req.Write(w)
	panicOnErr(err, "req(CONNECT).Write")
}

func readConnectResponse(buf *bufio.Reader) {
	_, err := buf.ReadString('\n')
	panicOnErr(err, "resp.Read connect resp")
	_, err = buf.ReadString('\n')
	panicOnErr(err, "resp.Read connect resp")
}

// TODO: REFACTOR
*/
/*func TestCurlMinusP(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.HandleConnectFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		return goproxy.MITM // default host
	})
	called := false
	proxy.HandleRequestFunc(func(ctx *goproxy.ProxyCtx) goproxy.Next {
		called = true
		return goproxy.NEXT
	})

	_, l := oneShotProxy(proxy, t)
	defer l.Close()

	cmd := exec.Command("curl", "-p", "-sS", "--proxy", l.URL, srv.URL+"/bobo")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != "bobo" {
		t.Error("Expected bobo, got", string(output))
	}
	if !called {
		t.Error("handler not called")
	}
}*//*


func TestSelfRequest(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	_, l := oneShotProxy(proxy, t)
	defer l.Close()
	if !strings.Contains(string(getOrFail(l.URL, http.DefaultClient, t)), "non-proxy") {
		t.Fatal("non proxy requests should fail")
	}
}
*/

/*
func TestHasGoproxyCA(t *testing.T) {
	proxy := goproxy.NewProxyHttpServer()
	proxy.HandleConnect(goproxy.AlwaysMitm)
	s := httptest.NewServer(proxy)

	proxyUrl, _ := url.Parse(s.URL)
	goproxyCA := x509.NewCertPool()
	goproxyCA.AddCert(goproxy.GoproxyCa.Leaf)

	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: goproxyCA}, Proxy: http.ProxyURL(proxyUrl)}
	client := &http.Client{Transport: tr}

	if resp := string(getOrFail(https.URL+"/bobo", client, t)); resp != "bobo" {
		t.Error("Wrong response when mitm", resp, "expected bobo")
	}
}
*/

func fatalOnErr(err error, msg string, t *testing.T) {
	if err != nil {
		t.Fatal(msg, err)
	}
}
func panicOnErr(err error, msg string) {
	if err != nil {
		println(err.Error() + ":-" + msg)
		os.Exit(-1)
	}
}


// Returns the requested header if it exists
type HeaderHandler struct{}

func (HeaderHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		panic(err)
	}
	//fmt.Println("[TEST] Header Handler called. Headers:", req)

	head := req.FormValue("header")
	if head == "" {
		panic("[ERROR] Form did not contain a header value")
	}

	//fmt.Println("[TEST] Header requested:", head)
	io.WriteString(w, req.Header.Get(head))
}

type QueryHandler struct{}

func (QueryHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		panic(err)
	}
	io.WriteString(w, req.Form.Get("result"))
}

func init() {
	http.DefaultServeMux.Handle("/bobo", ConstantHandler("bobo"))
	http.DefaultServeMux.Handle("/query", QueryHandler{})
	http.DefaultServeMux.Handle("/header", HeaderHandler{})
}

type ConstantHandler string

func (h ConstantHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("[TEST] Constant Handler received message. Returning", string(h))
	io.WriteString(w, string(h))
}

// Performs a simple HTTP/1.0 request directly over a connection. Calls proxy address
// but sends url via a GET header.
// headers must be properly formatted as key:value\r\n
func getraw(proxy string, url string, headers string) ([]byte, error) {
	// Make a connection to a whitelisted site
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		return nil, fmt.Errorf("Error dialing proxy [ERROR]: %s\n", err)
	}

	// Send as HTTP/1.0 so the host header isn't required
	fmt.Fprintf(conn, "GET " + url + " HTTP/1.0\r\n")
	fmt.Fprintf(conn, headers)
	fmt.Fprintf(conn, "\r\n")
	//_, err = bufio.NewReader(conn).ReadString('\n')
	response, err := ioutil.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("Error reading http stream from slack.com [ERROR]: %s\n", err)
	}
	conn.Close()
	return response, nil
}

// Sends a CONNECT request to a proxy. If successful returns the underlying conn back to the caller.
func connectraw(proxy string, host string) (net.Conn, error) {
	// Open a TCP connection to the proxy
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		return nil, fmt.Errorf("Error dialing proxy [ERROR]: %s\n", err)
	}

	// We're connecting as HTTP/1.1 so Host is required.
	fmt.Fprintf(conn, "CONNECT " + host + " HTTP/1.1\r\n")
	fmt.Fprintf(conn, "Host: " + host + "\r\n")
	fmt.Fprintf(conn, "\r\n")

	// Read each line until we get to two line feeds
	//firstcrlf := false
	foundOK := false

	reader := bufio.NewReader(conn)
	tp := textproto.NewReader(reader)
	for {
		line, _ := tp.ReadLine()
		fmt.Println("[TEST] connectraw - line:", line)
		if line == "" {
			//if firstcrlf {
			break
			//}
			//firstcrlf = true
		}
		if strings.Contains(string(line), "200 OK") {
			foundOK = true
		}

	}
	fmt.Println("[TEST] connectraw - reached EOF");
	//response, err := ioutil.ReadAll(conn)

	if err != nil {
		return nil, fmt.Errorf("Error reading http stream from slack.com [ERROR]: %s\n", err)
	}
	if foundOK {
		return conn, nil
	}
	return nil, fmt.Errorf("Received bad status code while connecting")
}



func get(url string, client *http.Client) ([]byte, error) {
	request, err := http.NewRequest("GET", url, nil)

	resp, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	txt, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return nil, err
	}
	return txt, nil
}


func getOrFail(url string, client *http.Client, t *testing.T) []byte {
	//fmt.Println("[TEST] getOrFail", url)
	txt, err := get(url, client)
	if err != nil {
		//fmt.Println("[ERROR] getOrFail error", err)
		t.Fatal("[ERROR] Can't fetch url", url, err)
	}
	//fmt.Println("[TEST] getOrFail returned", txt)
	return txt
}

func oneShotProxy(proxy *goproxy.ProxyHttpServer, port string) (client *http.Client, err error) {
	listenaddr := "127.0.0.1:" + port
	go proxy.ListenAndServe(listenaddr)
	time.Sleep(250 * time.Millisecond)
	proxyUrl, err := url.Parse("http://" + listenaddr)
	if err != nil {
		return
	}
	//fmt.Println("[TEST] oneShotProxy. Setting proxy transport to", proxyUrl)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig: acceptAllCerts}
	client = &http.Client{Transport: tr}
	return
}

func oneShotTLSProxy(proxy *goproxy.ProxyHttpServer, port string) (client *http.Client, err error) {
	listenaddr := "127.0.0.1:" + port
	go proxy.ListenAndServeTLS(listenaddr)
	time.Sleep(250 * time.Millisecond)
	proxyUrl, err := url.Parse("http://" + listenaddr)
	if err != nil {
		return
	}
	//fmt.Println("[TEST] oneShotProxy. Setting proxy transport to", proxyUrl)
	tr := &http.Transport{Proxy: http.ProxyURL(proxyUrl), TLSClientConfig: acceptAllCerts}
	client = &http.Client{Transport: tr}
	return
}

// Given an unencrypted connection, parses the headers and returns true if we got 200 OK back
func parseResponse(conn net.Conn) (bool) {
	// Read each line until we get to two line feeds
	foundOK := false
	//var response []byte

	reader := bufio.NewReader(conn)
	tp := textproto.NewReader(reader)
	for {
		line, _ := tp.ReadLine()
		fmt.Println("[TEST] Header", line)
		if line == "" {
			break
		}
		if strings.Contains(string(line), "200 OK") {
			foundOK = true
		}

	}

	return foundOK
}

func parseResponseBody(conn net.Conn) (string) {
	// Read each line until we get to two line feeds
	var response []byte


	reader := bufio.NewReader(conn)
	resp, _ := http.ReadResponse(reader, nil)

	response, _ = ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	// Attempt 2 - read until EOF
	//buf := make([]byte, 0, 4096) // big buffer
	//tmp := make([]byte, 2)     // using small tmo buffer for demonstrating
	//for {
	//	n, err := conn.Read(tmp)
	//	if err != nil {
	//		if err != io.EOF {
	//			fmt.Println("read error:", err)
	//		}
	//		break
	//	}
	//	fmt.Println("got", n, "bytes.")
	//	buf = append(buf, tmp[:n]...)
	//
	//}

	return string(response)
}