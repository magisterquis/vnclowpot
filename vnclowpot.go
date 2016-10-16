package main

/*
 * vnclowpot.go
 * Low-interaction VNC honeypot
 * By J. Stuart McMurray
 * Created 20191003
 * Last Modified 20191013
 */

/* Reference: https://tools.ietf.org/html/rfc6143 */

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

// VERSION is the RFB version string to send
const VERSION = "RFB 003.008\n"

// CHALLENGE is the VNC Auth challenge to send
const CHALLENGE = "AAAAAAAAAAAAAAAA"

func main() {
	var (
		laddr = flag.String(
			"l",
			"0.0.0.0:5900",
			"Listen `address`",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options]

Listens for VNC connections, performs the initial handshake either using only
VNC Authentication or offering all auth types (except VNC auth and no auth),
and logs the auth request to stdout.  Other logs (errors, etc.) go to stderr.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Listen */
	l, err := net.Listen("tcp", *laddr)
	if nil != err {
		log.Printf("Unable to listen on %v: %v", *laddr, err)
	}
	log.Printf("Listening on %v", l.Addr())

	/* Accept and handle clients */
	for {
		c, err := l.Accept()
		if nil != err {
			log.Fatalf("Error accepting connection: %v", err)
		}
		go handle(c)
	}
}

/* handle gets auth from a client and rejects it. */
func handle(c net.Conn) {
	defer c.Close()
	/* Send our version */
	if _, err := c.Write([]byte(VERSION)); nil != err {
		log.Printf(
			"%v Error before server version: %v",
			c.RemoteAddr(),
			err,
		)
		return
	}
	/* Get his version */
	ver := make([]byte, len(VERSION))
	n, err := io.ReadFull(c, ver)
	ver = ver[:n]
	if nil != err {
		log.Printf(
			"%v Disconnected before client version: %v",
			c.RemoteAddr(),
			err,
		)
		return
	}
	/* Versions have to match */
	if VERSION != string(ver) {
		log.Printf("%v Received bad version %q", c.RemoteAddr(), ver)
		/* Send an error message */
		if _, err := c.Write(append(
			[]byte{
				0,           /* 0 security types */
				0, 0, 0, 20, /* 20-character message */
			},
			/* Failure message */
			[]byte("Unsupported RFB version.")...,
		)); nil != err {
			log.Printf(
				"%v Unable to send unsupported version "+
					"message: %v",
				c.RemoteAddr(),
				err,
			)
		}
		return
	}
	/* Offer VNC Auth */
	/* TODO: Also, offer ALL the auths */
	if _, err := c.Write([]byte{
		0x01, /* We will send one offered auth type */
		0x02, /* VNC Auth */
	}); nil != err {
		log.Printf(
			"%v Unable to offer auth type: %v",
			c.RemoteAddr(),
			err,
		)
		return
	}
	/* Get security type client wants, which should be 2 for now */
	/* TODO: Offer more security types */
	buf := make([]byte, 1)
	_, err = io.ReadFull(c, buf)
	if nil != err {
		log.Printf(
			"%v Unable to read accepted security type: %v",
			c.RemoteAddr(),
			err,
		)
		return
	}
	if 0x02 != buf[0] {
		log.Printf(
			"%v Accepted unsupported security type %v",
			c.RemoteAddr(),
			buf[0],
		)
		return
	}
	/* Send challenge */
	if _, err := c.Write([]byte(CHALLENGE)); nil != err {
		log.Printf(
			"%v Unable to send challenge: %v",
			c.RemoteAddr(),
			err,
		)
		return
	}
	/* Get response */
	buf = make([]byte, 16)
	n, err = io.ReadFull(c, buf)
	buf = buf[:n]
	if nil != err {
		if 0 == n {
			log.Printf(
				"%v Unable to read auth response: %v",
				c.RemoteAddr(),
				err,
			)
		} else {
			log.Printf(
				"%v Received incomplete auth response: "+
					"%q (%v)",
				c.RemoteAddr(),
				buf,
				err,
			)
		}
		return
	}
	logSuc("%v Auth response: %q", c.RemoteAddr(), buf)
	/* Tell client auth failed */
	c.Write(append(
		[]byte{
			0, 0, 0, 1, /* Failure word */
			0, 0, 0, 29, /* Message length */
		},
		/* Failure message */
		[]byte("Invalid username or password.")...,
	))
}

/* slogger is a logger for successful authentication attempts.  It logs to
stdout. */
var slogger = log.New(os.Stdout, "", 0)

/* logSuc logs successful authentications */
func logSuc(f string, a ...interface{}) {
	slogger.Printf(f, a...)
}
