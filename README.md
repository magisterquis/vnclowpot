vnclowpot
=========
Low-interaction VNC honeypot.  Listens on a port and logs responses to a static
VNC Auth challenge.

It was inspired by (VNC-Pot)[https://github.com/SepehrHml/VNC-Pot], but does
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
At the moment, there's only one: the listen address (set with `-l`, 
0.0.0.0:5900 by default).  Pull requests with features are welcome.

Windows
-------
Should probably work.
