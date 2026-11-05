
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

func main() {
	const serverName = "example.com"

	// Step 1: Establish a TCP connection.
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	tcpConn, err := dialer.Dial(
		"tcp",
		net.JoinHostPort(serverName, "443"),
	)

	if err != nil {
		fmt.Println("TCP connection failed:", err)
		return
	}
	defer tcpConn.Close()

	// Set a deadline for the TLS handshake.
	err = tcpConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		fmt.Println("Setting deadline failed:", err)
		return
	}

	// Step 2: Configure TLS.
	config := &tls.Config{
		ServerName: serverName,
	}

	// Step 3: Wrap the existing TCP connection with TLS.
	tlsConn := tls.Client(tcpConn, config)

	// Step 4: Perform the TLS handshake.
	err = tlsConn.Handshake()
	if err != nil {
		fmt.Println("TLS handshake failed:", err)
		return
	}

	// Step 5: Display negotiated connection information.
	state := tlsConn.ConnectionState()

	fmt.Println("TLS handshake successful!")
	fmt.Printf("Negotiated TLS version: 0x%04x\n", state.Version)
	fmt.Printf(
		"Selected cipher: %s (0x%04x)\n",
		tls.CipherSuiteName(state.CipherSuite),
		state.CipherSuite,
	)
	fmt.Println("Handshake complete:", state.HandshakeComplete)

	if len(state.PeerCertificates) > 0 {
		fmt.Println(
			"Server certificate:",
			state.PeerCertificates[0].Subject,
		)
	}

	// Step 6: Close the TLS connection.
	tlsConn.Close()
}
