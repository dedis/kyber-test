module github.com/dedis/kyber-test

go 1.25.0

replace go.dedis.ch/kyber/v4 => ../kyber

require (
	go.dedis.ch/kyber/v3 v3.1.0
	go.dedis.ch/kyber/v4 v4.0.0
)

require (
	github.com/cronokirby/saferith v0.33.0 // indirect
	go.dedis.ch/fixbuf v1.0.3 // indirect
	golang.org/x/crypto v0.44.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
)
