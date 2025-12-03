module github.com/dedis/kyber-test

go 1.25.0

//when working locally with a newer version, uncomment the following line
//replace go.dedis.ch/kyber/v4 => ../kyber

require (
	go.dedis.ch/kyber/v3 v3.1.0
	go.dedis.ch/kyber/v4 v4.0.1-alpha.1
)

require (
	go.dedis.ch/fixbuf v1.0.3 // indirect
	golang.org/x/crypto v0.44.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
)
