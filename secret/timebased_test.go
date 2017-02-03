package secret

import (
	"testing"
)

func TestWithTime_GenerateText(t *testing.T) {
	wm := &TimeBasedToken{}
	err := wm.SetPrivateKey([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCllO6AqM8W55zTodYa29J/O1CDnFx2YBE8S7zBr+HIx/DNZxKr
WhsNWwdLFgmiG2Om0xvmkZ2OkYrDBOB4TTa67wG6xhIVFSUthen9AbjpWsKS9gm2
K9KWR/lpNB1Pf7t2SDj3zEBJN0zwzINNz4DMVZOSgRMk0HBtQ0c08nN5eQIDAQAB
AoGANl22CYxjonOdrGcAs4TlklzZTL00JrHYNuHvMfEbwx7S0746BQTqyPHQbTjp
JM61Y3sBOC0rfDoRQ4MAaL+Bbku1rd2km6VrGeYad52whcqe4wC2UjHkduwjTQQf
70Lpq/0unF+H1aTdp4DWsvBnYXDNUfbbi/Ph4tkcZZjiRgECQQDcNlJ6tX6Hmw7k
xePMasQtnk34/6es/8Rj4dcNQDrfqnhQkRtosxdeYwsNPNkKdm4J9dQdxEq6G8GO
HfZ2uv+ZAkEAwH3Fw/G2uNwM9b+MWH63C0A7YWMDABaxzzjYU8aB4JvFnOwDJc21
zPo3PGHAItUwxnSqhI3ZTw7BUxdRmTP04QJBAJPFeC+T3yaMbMAj8ytXcfHSyywO
EqzKrTUBddgUg+1XbYlS9nuZwlK6T85ASLz2n/zbE84tzJ96xLXjcWJXNfECQQCz
SfKUSWU51aw0kU81dgEj95XXZZN716eSLY5AqZp7DFwJh0J/SZVV8JDWKu39A7lE
f5H7mOuZWVL0A7o7CkvBAkBAyYThxhG0U3nHYskUevLpV3h+MAMnQ2B1zw6uAynF
5wF2maAnModcTp+CtROhpX066mZoZv+ovya+zB5vSfIJ
-----END RSA PRIVATE KEY-----
`))
	if err != nil {
		t.Fatal(err)
	}
	err = wm.SetPublicKey([]byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCllO6AqM8W55zTodYa29J/O1CD
nFx2YBE8S7zBr+HIx/DNZxKrWhsNWwdLFgmiG2Om0xvmkZ2OkYrDBOB4TTa67wG6
xhIVFSUthen9AbjpWsKS9gm2K9KWR/lpNB1Pf7t2SDj3zEBJN0zwzINNz4DMVZOS
gRMk0HBtQ0c08nN5eQIDAQAB
-----END PUBLIC KEY-----`))
	if err != nil {
		t.Fatal(err)
	}
	wm.SetSalt("我勒个去")
	text, err := wm.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if !wm.Verify(text) {
		t.Fatal("校验失败")
	}
}
