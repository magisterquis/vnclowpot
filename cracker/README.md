cracker
=======
Cracker is a small program to perform a wordlist attack on VNC handshakes
in John The Ripper format.

Please run it with `-h` for a complete listing of options.

For legal use only.

Example
-------
```bash
./cracker -p ~/.john/john.pot -w /tmp/rockyou.txt ./vnclowpot.log
```

Details
-------
Cracker extracts John The Ripper-formatted VNC handshakes from the input
file(s) (or the standard input if no files are given), and tries each password
in the wordlist against each handshake.

As VNC limits passwords to 8 characters and Cracker performs no deduplication,
passwords may be tried multiple times (e.g. if both `password` and
`password123` are in the wordlist.

Cracker does not crack in parallel.  Pull requests are welcome.

Potfile
-------
A John The Ripper-compatible potfile (or, really, the one JtR uses), can be
used with the `-p` option to speed up cracking by first checking the potfile
for known handshake/password pairs.
