tester
======
Tester can be used to generate hashes for testing vnclowpot, as well as testing
VNC security.

Please run it with `-h` for a complete listing of options

For legal use only.

Example
-------
```bash
./tester -wordlist passwords.txt 192.168.1.2 192.168.1.3
```

Details
-------
Tester is nothing more than a VNC brute-forcer with the nice side-effect of
causing vnclowpot to log known hashes (plus a handful of features useful for
pentesters and such).  Please don't use it for illegal purposes.

Only protocol 3.8 with VNC Authentication is supported.  As this is what is
used by vnclowpot, there are no plans to support other protocol versions.  Pull
requests are welcome.
