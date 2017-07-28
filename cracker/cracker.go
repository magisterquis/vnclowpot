package main

/*
 * cracker.go
 * VNC handshake dictionary attacker
 * By J. Stuart McMurray
 * Created 20170720
 * Last Modified 20170728
 */

import (
	"bufio"
	"crypto/des"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

/* handshakes holds the challenge -> responses map */
type handshakes map[[16]byte]map[[16]byte]struct{}

// REVERSEDBYTE is a lookup table to get the byte backwards.  Not in the
// RFC, but it seems to be how it works.
var REVERSEDBYTE = [256]byte{
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

// HSRE is the regular expression to grab a handshake
var HSRE = regexp.MustCompile(`\$vnc\$\*([0-9A-Fa-f]{32})\*([0-9A-Fa-f]{32})`)

// POTRE is the regular expression to get a line from the potfile
var POTRE = regexp.MustCompile(
	`\$vnc\$\*([0-9A-Fa-f]{32})\*([0-9A-Fa-f]{32}):(\S+)`,
)

/* slog is a logger for stdout */
var slog = log.New(os.Stdout, "", log.LstdFlags)

func main() {
	var (
		pot = flag.String(
			"p",
			"",
			"Pot `file`",
		)
		wordlist = flag.String(
			"w",
			"rockyou.txt",
			"Wordlist `file`",
		)
		printFail = flag.Bool(
			"f",
			false,
			"Print handshakes which were not cracked",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %v [options] [handshakefile [handshakefile...]]

Attempts to crack VNC handshakes, which should be of the form

$vnc$*challenge*response

(e.g. $vnc$*00000000000000000000000000000000*7909B24AE2F2EDC97909B24AE2F2EDC9
for a challenge of all null bytes and 7909B24AE2F2EDC97909B24AE2F2EDC9 sent
in response)

A John-the-Ripper potfile may be used to avoid searching for known hashes.

If "-" is given as the handshakefile or no handshake files are given,
handshakes will be read from the standandard input.  Cracking will not start
until EOF on the standand input.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Make sure we can open the potfile */
	var (
		pa  *os.File /* Appendable potfile */
		pr  *os.File /* Read-only potfile */
		err error
	)
	if "" != *pot {
		pa, err = os.OpenFile(
			*pot,
			os.O_CREATE|os.O_APPEND|os.O_WRONLY,
			0600,
		)
		if nil != err {
			log.Fatalf(
				"Unable to open potfile %q for updating: %v",
				*pot,
				err,
			)
		}
		pr, err = os.Open(*pot)
		if nil != err {
			log.Fatalf(
				"Unable to open potfile %q for reading: %v",
				*pot,
				err,
			)
		}
		log.Printf("Opened potfile %v", pr.Name())
	}

	/* Handshakes from stdin */
	names := flag.Args()
	if 0 == len(names) {
		names = append(names, "-")
	}
	hs := make(handshakes)
	tot := 0

	/* Read handshakes from all the files */
	for _, fn := range flag.Args() {
		n, err := readHandshakes(fn, hs)
		if nil != err {
			if "-" == fn {
				fn = "standard input"
			}
			log.Fatalf(
				"Unable to read handshakes "+
					"from %v: %v",
				fn,
				err,
			)
		}
		log.Printf("Read %v handshakes from %v", n, fn)
		tot += n
	}
	if 0 == tot {
		log.Fatalf("No handshakes to crack")
	}
	log.Printf("Attempting to crack %v handshakes", tot)

	/* Remove the ones in the potfile */
	cracked := 0
	if nil != pr {
		n, err := checkPot(hs, pr)
		if nil != err {
			log.Fatalf(
				"Unable to check handshakes against "+
					"potfile: %v",
				err,
			)
		}
		/* Give up if there's none left */
		if 0 == len(hs) {
			return
		}
		pr.Close()
		cracked += n
	}

	/* Try to crack the remaining handshakes */
	n, err := crack(hs, pa, *wordlist)
	if nil != err {
		log.Fatalf("Error: %v", err)
	}
	if *printFail {
		for c, rs := range hs {
			for r := range rs {
				slog.Printf("NOTFOUND $vnc$*%02X*%02X", c, r)
			}
		}
	}
	log.Printf("Found passwords for %v/%v handshakes", cracked+n, tot)
	return
}

/* readHandshakes attempts to pull handshakes out of the file named fn.  It
returns the number of handshakes read and sticks the handshakes into hs. */
func readHandshakes(fn string, hs handshakes) (int, error) {
	f := os.Stdin
	/* Try to open the file, if given */
	if "-" != fn {
		var err error
		f, err = os.Open(fn)
		if nil != err {
			return 0, err
		}
		defer f.Close()
	}
	/* Try to grab handshakes from each line of the file */
	n := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		/* Parse out handshakes */
		ms := HSRE.FindAllStringSubmatch(scanner.Text(), -1)
		/* Stick them in the map */
		for _, m := range ms {
			if 3 != len(m) {
				log.Panicf("%#v", m)
			}
			c, err := decodeHex(m[1])
			if nil != err {
				log.Panicf("Short challenge in %v", m)
			}
			r, err := decodeHex(m[2])
			if nil != err {
				log.Panicf("Short response in %v", m)
			}
			addHandshake(hs, c, r)
			n++
		}
	}
	if err := scanner.Err(); nil != err {
		return 0, err
	}
	return n, nil
}

/* addHandshake adds the challenge/response pair to the set of handshakes */
func addHandshake(hs handshakes, c, r [16]byte) {
	/* Make sure there's a map for the challenge */
	if _, ok := hs[c]; !ok {
		hs[c] = make(map[[16]byte]struct{})
	}
	hs[c][r] = struct{}{}
}

/* delHandshake removes the challenge/response pair from the set of
handshakes */
func delHandshake(hs handshakes, c, r [16]byte) {
	/* Make sure the handshake exists */
	if _, ok := hs[c]; !ok {
		log.Panicf("Challenge %02X not known", c)
	}
	if _, ok := hs[c][r]; !ok {
		log.Panicf("Handshakes %02X->%02X not known", c, r)
	}
	/* Remove the response */
	delete(hs[c], r)
	/* If there's no more responses for the challenge, remove it */
	if 0 == len(hs[c]) {
		delete(hs, c)
	}
}

/* decodeHex turns a hex string into a [16]byte */
func decodeHex(s string) ([16]byte, error) {
	var a [16]byte
	b, err := hex.DecodeString(s)
	if nil != err {
		return a, err
	}
	if 16 != len(b) {
		return a, fmt.Errorf(
			"%s decodes to non-16 length  %v",
			s,
			len(b),
		)
	}
	copy(a[:], b)
	return a, nil
}

/* crack is where the magic happens.  Passwords from the wordlist are tried
against the handshakes in hs.  If pot is not nil, it is used to store cracked
handshakes.  Cracked handshakes are removed from hs. */
func crack(hs handshakes, pot *os.File, wordlist string) (int, error) {
	/* Try to open the wordlist */
	w, err := os.Open(wordlist)
	if nil != err {
		return 0, err
	}
	defer w.Close()
	nCracked := 0 /* Number of handshakes cracked */
	/* Loop over password guesses */
	scanner := bufio.NewScanner(w)
	for scanner.Scan() {
		/* Get a password guess */
		pass := scanner.Text()
		n, err := tryPass(hs, pot, pass)
		if nil != err {
			return 0, err
		}
		nCracked += n
	}
	return nCracked, nil
}

/* tryPass tries the password against all of the handshakes in hs.  If a match
is found, a message is printed and the handshake is removed from hs, and, if
pot is not nil, the potfile is updated.  The number of cracked handshakes is
returned. */
func tryPass(hs handshakes, pot *os.File, pass string) (int, error) {
	p := []byte(pass)
	/* Turn password into exactly 8 bytes */
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
		return 0, err
	}

	/* Buffer for expected response */
	var e [16]byte

	/* Loop over challenges */
	nCracked := 0
	for c, rs := range hs {
		/* Encrypt challenge with password */
		d.Encrypt(e[0:8], c[0:8])
		d.Encrypt(e[8:16], c[8:16])

		/* Check each response to see if it's the same */
		for r := range rs {
			/* If not, a different password was used */
			if e != r {
				continue
			}
			/* Passwords are the same, log it */
			nCracked++
			if err := logSuccess(
				c,
				r,
				string(p),
				pot,
			); nil != err {
				return nCracked, err
			}
			delHandshake(hs, c, r)
			/* No need to check the other responses, only one will
			match */
			break
		}
	}
	return nCracked, nil
}

/* logSuccess logs the successful cracking of challenge c and response r with
password p, and sticks it in the potfile if not nil. */
func logSuccess(c, r [16]byte, p string, pot *os.File) error {
	/* String indicating cracking */
	ans := fmt.Sprintf(
		"$vnc$*%02X*%02X:%s",
		c,
		r,
		strings.TrimRight(p, "\x00"),
	)
	/* If we have a potfile, update it */
	if nil != pot {
		if _, err := fmt.Fprintf(pot, "%s\n", ans); nil != err {
			return nil
		}
	}
	/* Tell the user */
	slog.Printf("FOUND %s", ans)
	return nil
}

/* checkPot checks the potfile for the handshakes.  It removes challenge/
response pairs with found handshakes and returns the number of passwords
found. */
func checkPot(hs handshakes, pr *os.File) (int, error) {
	nFound := 0
	scanner := bufio.NewScanner(pr)
	for scanner.Scan() {
		/* Extract the interesting bits */
		m := POTRE.FindStringSubmatch(scanner.Text())
		if nil == m {
			continue
		}
		/* Convert to arrays to search for in the handshakes */
		c, err := decodeHex(m[1])
		if nil != err {
			log.Panicf("Short pot challenge in %v", m)
		}
		r, err := decodeHex(m[2])
		if nil != err {
			log.Panicf("Short pot response in %v", m)
		}
		p := m[3]
		/* Check if the challenge and response are known */
		if _, ok := hs[c]; !ok {
			continue
		}
		if _, ok := hs[c][r]; !ok {
			continue
		}
		slog.Printf("POT $vnc$*%02X*%02X:%s", c, r, p)
		delHandshake(hs, c, r)
		nFound++
	}
	if err := scanner.Err(); nil != err {
		return nFound, err
	}
	return nFound, nil
}

//$vnc$*00000000000000000000000000000000*7909B24AE2F2EDC97909B24AE2F2EDC9

//	p := make([]byte, 8)
//	c := make([]byte, 8)
//	e, err := des.NewCipher(k)
//	if nil != err {
//		panic(err)
//	}
//	e.Encrypt(c, p)
//	fmt.Printf("%02X\n", c)

//	k := []byte("kitten\x00\x00")
//	for i, b := range k {
//		k[i] = reversedByte[b]
//	}
