package apns

import (
	"crypto/tls"
	"net"
	"strings"
	"appengine"
	"sync"
	"encoding/binary"
	"bytes"
	"errors"
	"time"
	"fmt"
)

// Client contains the fields necessary to communicate
// with Apple, such as the gateway to use and your
// certificate contents.
//
// You'll need to provide your own CertificateFile
// and KeyFile to send notifications. Ideally, you'll
// just set the CertificateFile and KeyFile fields to
// a location on drive where the certs can be loaded,
// but if you prefer you can use the CertificateBase64
// and KeyBase64 fields to store the actual contents.
type Client struct {
	sync.Mutex

	ctx			  appengine.Context

	Gateway           string
	CertificateFile   string
	CertificateBase64 string
	KeyFile           string
	KeyBase64         string
	DialFunction      func(address string) (net.Conn, error)
	closed bool

	pushNotifCh	  chan *PushNotification
	FailCh		  chan *PushNotificationResponse

	SocketCloseCh chan struct{}

	doneCh		  chan struct{}
	apnsRespCh	  chan []byte

	certificate		  tls.Certificate
	apnsConn		*tls.Conn
}

type errResponse struct {
	Command uint8
	Status uint8
	Identifier int32
}


// BareClient can be used to set the contents of your
// certificate and key blocks manually.
func BareClient(ctx appengine.Context, gateway, certificateBase64, keyBase64 string) (c *Client) {
	c = new(Client)
	c.ctx = ctx
	c.Gateway = gateway
	c.CertificateBase64 = certificateBase64
	c.KeyBase64 = keyBase64
	c.DialFunction = func(address string) (net.Conn, error) { return net.Dial("tcp", address) }
	c.closed = false
	return
}

// NewClient assumes you'll be passing in paths that
// point to your certificate and key.
func NewClient(ctx appengine.Context, gateway, certificateFile, keyFile string) (c *Client) {
	c = new(Client)
	c.ctx = ctx
	c.Gateway = gateway
	c.CertificateFile = certificateFile
	c.KeyFile = keyFile
	c.DialFunction = func(address string) (net.Conn, error) { return net.Dial("tcp", address) }
	return
}

func (client *Client) IsOpen() bool {
	if client.closed {
		return false
	}
	return client.apnsConn != nil
}

func (client *Client) IsClosed() bool {
	return !client.IsOpen()
}

func (client *Client) Open() error {
	if client.apnsConn == nil {
		return client.openConnection()
	}
	return nil
}

func (client *Client) openConnection() error {
	err := client.getCertificate()
	if err != nil {
		client.ctx.Errorf("Error getting cert: %v", err)
		return err
	}

	gatewayParts := strings.Split(client.Gateway, ":")
	conf := &tls.Config{
		Certificates: []tls.Certificate{client.certificate},
		ServerName:   gatewayParts[0],
	}

	conn, err := client.DialFunction(client.Gateway)
	if err != nil {
		client.ctx.Errorf("Error dialing on gateway: %v, %v", client.Gateway, err)
		return err
	}

	tlsConn := tls.Client(conn, conf)
	err = tlsConn.Handshake()
	if err != nil {
		return fmt.Errorf("Handshake err: %s", err.Error())
	}

	client.apnsConn = tlsConn
	client.initChans()
	client.closed = false
	go client.loop()
	return nil
}

func (client *Client) initChans() {
	client.pushNotifCh = make(chan *PushNotification)
	client.FailCh = make(chan *PushNotificationResponse)

	client.SocketCloseCh = make(chan struct{})

	client.doneCh = make(chan struct{})

	client.apnsRespCh = make(chan []byte)
}

func (client *Client) Close() {
	client.ctx.Debugf("Closing %s", client.Gateway)

	client.Lock()
	defer client.Unlock()

	if client.apnsConn == nil {
		client.ctx.Infof("apns connection nil so not closing any channels on client close")
		return
	}
	close(client.SocketCloseCh)
	close(client.doneCh)
	client.apnsConn.Close()
	client.apnsConn = nil
	client.closed = true
}

func (client *Client) EnqueuePushNotif(pn *PushNotification) error {
	select {
	case client.pushNotifCh <- pn:
		return nil
	case <- client.doneCh:
		return errors.New("Done channel was fired probably because client was closed.")
	case <- time.Tick(10 * time.Second):
		return fmt.Errorf("Timeout trying to enqueue push notif: %+v", pn)
	}
}

func (client *Client) readLoop() {
	client.ctx.Debugf("Starting read loop")
	outter: for {
		if client.apnsConn == nil {
			client.ctx.Infof("apnsconn is nil, returning from read loop")
			return
		}
		select {
		case <- time.Tick(time.Millisecond * 1200):
			client.ctx.Infof("Tyring to read response from socket")
		case <- client.doneCh:
			client.ctx.Infof("Closing read loop as client has been closed")
			return
		}

		buffer := make([]byte, 6, 6)
		_, err := client.apnsConn.Read(buffer)
		if err != nil {
			client.ctx.Warningf("Got error reading apnsConn: %v", err)
			for strings.HasPrefix(err.Error(), "API error 1") {
				time.Sleep(time.Millisecond * 100)
				continue outter
			}
			client.ctx.Warningf("Closing - err: %+v", err)
			client.Close()
		}
		client.apnsRespCh <- buffer
	}
}

func (client *Client) loop() {
	firstRun := false
	outer: for {
		client.ctx.Infof("Next iteration is starting")
		select {
		case <-client.doneCh:
			client.ctx.Debugf("DoneCh finishing up loop")
			return
		case pn := <-client.pushNotifCh:
			if pn == nil {
				client.ctx.Errorf("Client got nil push notification.")
				continue outer
			}
			// resp := client.Send(pn)
			// client.ctx.Debugf("Sending pn got resp: %+v", resp)

			client.ctx.Debugf("Got push notif from channel")
			payload, err := pn.ToBytes()
			if err != nil {
				client.ctx.Errorf("Erorr serializing pn to bytes: %v", err)
				client.Close()
			}

			client.ctx.Debugf("Writing notif to socket")
			_, err = client.apnsConn.Write(payload)
			if err != nil {
				client.ctx.Warningf("1 Got error writing apnsConn: %v", err)
				client.ctx.Warningf("Closing")
				client.Close()
			}
			client.ctx.Debugf("Succeeded write")

			if !firstRun {
				firstRun = true
				go client.readLoop()
			}
		case buffer := <-client.apnsRespCh:
			client.ctx.Debugf("Got buffer from respch")
			errRsp := &errResponse{
				Command: uint8(buffer[0]),
				Status:  uint8(buffer[1]),
			}

			if err := binary.Read(bytes.NewBuffer(buffer[2:]), binary.BigEndian, &errRsp.Identifier); err != nil {
				client.ctx.Errorf("Read identifier err: %v", err)
				return
			}

			client.ctx.Debugf("Got response of: %+v", errRsp)

			resp := new(PushNotificationResponse)
			resp.Success = false
			client.FailCh <- resp
		}
	}
}

// Send connects to the APN service and sends your push notification.
// Remember that if the submission is successful, Apple won't reply.
func (client *Client) Send(pn *PushNotification) (resp *PushNotificationResponse) {
	resp = new(PushNotificationResponse)

	payload, err := pn.ToBytes()
	if err != nil {
		resp.Success = false
		resp.Error = err
		return
	}

	err = client.ConnectAndWrite(resp, payload)
	if err != nil {
		resp.Success = false
		resp.Error = err
		return
	}

	resp.Success = true
	resp.Error = nil

	return
}

// ConnectAndWrite establishes the connection to Apple and handles the
// transmission of your push notification, as well as waiting for a reply.
//
// In lieu of a timeout (which would be available in Go 1.1)
// we use a timeout channel pattern instead. We start two goroutines,
// one of which just sleeps for TimeoutSeconds seconds, while the other
// waits for a response from the Apple servers.
//
// Whichever channel puts data on first is the "winner". As such, it's
// possible to get a false positive if Apple takes a long time to respond.
// It's probably not a deal-breaker, but something to be aware of.
func (client *Client) ConnectAndWrite(resp *PushNotificationResponse, payload []byte) (err error) {
	var cert tls.Certificate

	if len(client.CertificateBase64) == 0 && len(client.KeyBase64) == 0 {
		// The user did not specify raw block contents, so check the filesystem.
		cert, err = tls.LoadX509KeyPair(client.CertificateFile, client.KeyFile)
	} else {
		// The user provided the raw block contents, so use that.
		cert, err = tls.X509KeyPair([]byte(client.CertificateBase64), []byte(client.KeyBase64))
	}

	if err != nil {
		return err
	}

	gatewayParts := strings.Split(client.Gateway, ":")
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName: gatewayParts[0],
	}

	conn, err := client.DialFunction(client.Gateway)
	if err != nil {
		return err
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, conf)
	err = tlsConn.Handshake()
	if err != nil {
		return err
	}
	defer tlsConn.Close()

	_, err = tlsConn.Write(payload)
	if err != nil {
		return err
	}

	// Create one channel that will serve to handle
	// timeouts when the notification succeeds.
	timeoutChannel := make(chan bool, 1)
	go func() {
		time.Sleep(time.Second * TimeoutSeconds)
		timeoutChannel <- true
	}()

	// This channel will contain the binary response
	// from Apple in the event of a failure.
	responseChannel := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 6, 6)
		tlsConn.Read(buffer)
		responseChannel <- buffer
	}()

	// First one back wins!
	// The data structure for an APN response is as follows:
	//
	// command    -> 1 byte
	// status     -> 1 byte
	// identifier -> 4 bytes
	//
	// The first byte will always be set to 8.
	select {
	case r := <-responseChannel:
		resp.Success = false
		resp.AppleResponse = ApplePushResponses[r[1]]
		err = errors.New(resp.AppleResponse)
	case <-timeoutChannel:
		resp.Success = true
	}

	return err
}

// From: https://github.com/quexer/apns/blob/master/client.go
// Returns a certificate to use to send the notification.
// The certificate is only created once to save on
// the overhead of the crypto libraries.
func (client *Client) getCertificate() error {
	var err error

	/*if client.certificate.PrivateKey == nil {*/
		if len(client.CertificateBase64) == 0 && len(client.KeyBase64) == 0 {
			// The user did not specify raw block contents, so check the filesystem.
			client.certificate, err = tls.LoadX509KeyPair(client.CertificateFile, client.KeyFile)
		} else {
			// The user provided the raw block contents, so use that.
			client.certificate, err = tls.X509KeyPair([]byte(client.CertificateBase64), []byte(client.KeyBase64))
		}
	/*}*/

	return err
}
