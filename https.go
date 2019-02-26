package goproxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"fmt"
	"context"
	"github.com/winston/shadownetwork"
)

// returns only the hostname
func stripPort(s string) string {
	ix := strings.IndexRune(s, ':')
	if ix == -1 {
		return s
	}
	return s[:ix]
}


// RLS 2/15/2018 - New DialContext routines. Preferred because these allow the transport
// to cancel dials as soon as they are no longer needed.
func (proxy *ProxyHttpServer) dialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	//fmt.Printf("[DEBUG] https.go/dialContext() %s\n", addr)
	// ctx must be non-nil. Ensure we always have one.
	if ctx == nil {
		ctx = context.Background()
	}

	privatenetwork, ok := ctx.Value(shadownetwork.PrivateNetworkKey).(bool)
	//fmt.Println("[DEBUG] privatenetwork", privatenetwork)
	if ok && privatenetwork && proxy.PrivateNetwork != nil {
		//fmt.Printf("[DEBUG] https.go/dialContext() -> forwarding through private network [%s]. PrivateNetwork:\n", addr, )
		shadowtr := proxy.PrivateNetwork.Transport(addr)
		if shadowtr != nil {
			ctx2 := context.WithValue(ctx, shadownetwork.ShadowTransportKey, shadowtr)
			return shadowtr.Transport.(*shadownetwork.KCPTransport).DialContext(ctx2, network, addr)
		}
	} //else {
		//fmt.Printf("[DEBUG] https.go/dialContext() -> Local network [%s]\n", addr)
	//}


	if proxy.Transport.DialContext != nil {
		//fmt.Printf("[DEBUG] https.go/dialContext() -> Custom DialContext [%s] %v\n", addr, ctx)
		// Call the custom dialer, if we have one.
		return proxy.Transport.DialContext(ctx, network, addr)
	}

	// This is the default dialer
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// Don't use - this is for unit testing purposes only.
func (proxy *ProxyHttpServer) TestConnectDialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	return proxy.connectDialContext(ctx, network, addr)
}

func (proxy *ProxyHttpServer) connectDialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	//fmt.Println("[DEBUG] connectDialContext()")
	//panic("stack trace")
	if proxy.ConnectDialContext == nil {
		// This is the default for https connections
		return proxy.dialContext(ctx, network, addr)
	}

	// ctx must be non-nil. Ensure we always have one.
	if ctx == nil {
		ctx = context.Background()
	}

	fmt.Println("[DEBUG] connectDialContext() 2")
	// This would be hit if we defined a custom dialer (we don't)
	return proxy.ConnectDialContext(ctx, network, addr)
}

// Returns a context dialer for a proxy if specified by the environment
func dialerFromEnvContext(proxy *ProxyHttpServer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	https_proxy := os.Getenv("HTTPS_PROXY")
	if https_proxy == "" {
		https_proxy = os.Getenv("https_proxy")
	}
	if https_proxy == "" {
		return nil
	}
	return proxy.NewConnectDialToProxyContext(https_proxy)
}

func (proxy *ProxyHttpServer) NewConnectDialToProxyContext(https_proxy string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	u, err := url.Parse(https_proxy)
	if err != nil {
		return nil
	}
	if u.Scheme == "" || u.Scheme == "http" {
		if strings.IndexRune(u.Host, ':') == -1 {
			u.Host += ":80"
		}
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			connectReq := &http.Request{
				Method: "CONNECT",
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: make(http.Header),
			}
			c, err := proxy.dialContext(ctx, network, u.Host)
			if err != nil {
				return nil, err
			}
			connectReq.Write(c)
			// Read response.
			// Okay to use and discard buffered reader here, because
			// TLS server will not speak until spoken to.
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, connectReq)
			if err != nil {
				c.Close()
				return nil, err
			}
			if resp.StatusCode != 200 {
				resp, _ := ioutil.ReadAll(resp.Body)
				c.Close()
				return nil, errors.New("proxy refused connection" + string(resp))
			}
			return c, nil
		}
	}
	if u.Scheme == "https" {
		if strings.IndexRune(u.Host, ':') == -1 {
			u.Host += ":443"
		}
		return func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := proxy.dialContext(ctx, network, u.Host)
			if err != nil {
				return nil, err
			}
			c = tls.Client(c, proxy.Transport.TLSClientConfig)
			connectReq := &http.Request{
				Method: "CONNECT",
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: make(http.Header),
			}
			connectReq.Write(c)
			// Read response.
			// Okay to use and discard buffered reader here, because
			// TLS server will not speak until spoken to.
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, connectReq)
			if err != nil {
				c.Close()
				return nil, err
			}
			if resp.StatusCode != 200 {
				body, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 500))
				resp.Body.Close()
				c.Close()
				return nil, errors.New("proxy refused connection" + string(body))
			}
			return c, nil
		}
	}
	return nil
}

/* Legacy versions of Dial code */

func (proxy *ProxyHttpServer) dial(network, addr string) (c net.Conn, err error) {
	if proxy.Transport.Dial != nil {
		// Call the custom dialer, if we have one (we don't)
		return proxy.Transport.Dial(network, addr)
	}

	// This is the default dialer
	return net.Dial(network, addr)
}


func (proxy *ProxyHttpServer) connectDial(network, addr string) (c net.Conn, err error) {

	if proxy.ConnectDial == nil {
		// This is the default for https connections
		return proxy.dial(network, addr)
	}

	// If we're pointing to another proxy server, this would be called.
	return proxy.ConnectDial(network, addr)
}

func dialerFromEnv(proxy *ProxyHttpServer) func(network, addr string) (net.Conn, error) {
	https_proxy := os.Getenv("HTTPS_PROXY")
	if https_proxy == "" {
		https_proxy = os.Getenv("https_proxy")
	}
	if https_proxy == "" {
		return nil
	}
	return proxy.NewConnectDialToProxy(https_proxy)
}

func (proxy *ProxyHttpServer) NewConnectDialToProxy(https_proxy string) func(network, addr string) (net.Conn, error) {
	u, err := url.Parse(https_proxy)
	if err != nil {
		return nil
	}
	if u.Scheme == "" || u.Scheme == "http" {
		if strings.IndexRune(u.Host, ':') == -1 {
			u.Host += ":80"
		}
		return func(network, addr string) (net.Conn, error) {
			connectReq := &http.Request{
				Method: "CONNECT",
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: make(http.Header),
			}
			c, err := proxy.dial(network, u.Host)
			if err != nil {
				return nil, err
			}
			connectReq.Write(c)
			// Read response.
			// Okay to use and discard buffered reader here, because
			// TLS server will not speak until spoken to.
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, connectReq)
			if err != nil {
				c.Close()
				return nil, err
			}
			if resp.StatusCode != 200 {
				resp, _ := ioutil.ReadAll(resp.Body)
				c.Close()
				return nil, errors.New("proxy refused connection" + string(resp))
			}
			return c, nil
		}
	}
	if u.Scheme == "https" {
		if strings.IndexRune(u.Host, ':') == -1 {
			u.Host += ":443"
		}
		return func(network, addr string) (net.Conn, error) {
			c, err := proxy.dial(network, u.Host)
			if err != nil {
				return nil, err
			}
			c = tls.Client(c, proxy.Transport.TLSClientConfig)
			connectReq := &http.Request{
				Method: "CONNECT",
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: make(http.Header),
			}
			connectReq.Write(c)
			// Read response.
			// Okay to use and discard buffered reader here, because
			// TLS server will not speak until spoken to.
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, connectReq)
			if err != nil {
				c.Close()
				return nil, err
			}
			if resp.StatusCode != 200 {
				body, _ := ioutil.ReadAll(io.LimitReader(resp.Body, 500))
				resp.Body.Close()
				c.Close()
				return nil, errors.New("proxy refused connection" + string(body))
			}
			return c, nil
		}
	}
	return nil
}
