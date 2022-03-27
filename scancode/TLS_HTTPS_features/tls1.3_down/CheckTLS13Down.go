package tls

import (
	"bytes"
	"net"
	"time"
)

func Checktls13downgrade(domain string, ip string, port string, maxversion uint16)(flag bool,error string){
	var buf bytes.Buffer
	buf.WriteString(ip)
	buf.WriteString(":")
	buf.WriteString(port)
	fullAddr := buf.String()

	tlsConfig := &Config{
		InsecureSkipVerify: true,
		// Use SNI
		ServerName: domain,
		MaxVersion: maxversion,
	}

	timeout := 15*time.Second
	conn, err := net.DialTimeout("tcp", fullAddr, timeout)
	if err != nil{
		return false, err.Error()
	}

	err = conn.SetDeadline(time.Now().Add(timeout))
	if err != nil{
		return false, err.Error()
	}

	c := &Conn{
		conn:     conn,
		config:   tlsConfig,
		isClient: true,
	}

	hello, _, err := c.makeClientHello()
	if err != nil {
		return false, err.Error()
	}
	c.serverName = hello.serverName

	cacheKey, session, _, _ := c.loadSession(hello)
	if cacheKey != "" && session != nil {
		defer func() {
			// If we got a handshake failure when resuming a session, throw away
			// the session ticket. See RFC 5077, Section 3.2.
			//
			// RFC 8446 makes no mention of dropping tickets on failure, but it
			// does require servers to abort on invalid binders, so we need to
			// delete tickets to recover from a corrupted PSK.
			if err != nil {
				c.config.ClientSessionCache.Put(cacheKey, nil)
			}
		}()
	}

	if _, err := c.writeRecord(recordTypeHandshake, hello.marshal()); err != nil {
		return false, err.Error()
	}


	msg, err := c.readHandshake()
	if err != nil {
		return false, err.Error()
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok{

		return false, err.Error()
	}

	if err := c.pickTLSVersion(serverHello); err != nil {
		return false, err.Error()
	}
	
	if maxversion == VersionTLS12{
		if string(serverHello.random[24:]) == downgradeCanaryTLS12{
			return true, ""
		}else{
			return false, "No TLS1.3 downgrade protection"
		}
	}
	if maxversion == VersionTLS11 || maxversion == VersionTLS10 {
		if string(serverHello.random[24:]) == downgradeCanaryTLS11{
			return true, ""
		}else{
			return false, "No TLS1.3 downgrade protection"
		}
	}

	return false, "No TLS1.3 downgrade protection"
}
