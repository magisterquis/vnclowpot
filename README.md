vnclowpot
=========
Low-interaction VNC honeypot.  Listens on a port and logs responses to a static
VNC Auth challenge.

It was inspired by [VNC-Pot](https://github.com/SepehrHml/VNC-Pot), but does
not have any dependencies outside the go standard library.

Setup and Install
-----------------
```bash
go get github.com/magisterquis/vnclowpot
go install github.com/magisterquis/vnclowpot
vnclowpot
```

Options
-------
There's only two options:
- The listen address can be changed with `-l`
- John The Ripper-compatible lines can be generated with `-j` (and will need
  to be extracted from the log messages with something like `cut -f 4 -d ' '`).
Pull requests are welcome.

Windows
-------
Should probably work.
