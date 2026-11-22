module github.com/go-authn/pkcs12/oracle

go 1.27.4

replace github.com/go-authn/pkcs12 => ../

require (
	github.com/go-authn/pkcs12 v0.0.0-00010101000000-000000000000
	software.sslmate.com/src/go-pkcs12 v0.7.4
)

require golang.org/x/crypto v0.11.0 // indirect
