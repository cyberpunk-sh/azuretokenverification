package azuretokenverification

// Define a structure to hold JWKS data
type JWKS struct {
	Keys []JWKey `json:"keys"`
}

// Define a structure to represent a JSON Web Key
type JWKey struct {
	Kid    string   `json:"kid"` // Key ID
	Kty    string   `json:"kty"` // Key type (e.g., RSA)
	Alg    string   `json:"alg"` // Algorithm (e.g., RS256)
	Use    string   `json:"use"` // Usage (e.g., "sig" for signature)
	N      string   `json:"n"`   // Modulus (for RSA)
	E      string   `json:"e"`   // Exponent (for RSA)
	X5c    []string `json:"x5c"` // Certificate chain
	X5t    string   `json:"x5t"` // (X.509 Certificate SHA-1 Thumbprint)
	Issuer string   `json:"issuer"`
}

func DecodePEM(cert string) string {
	pem := "-----BEGIN CERTIFICATE-----\n"
	chunks := len(cert) / 64
	for i := 0; i < chunks; i++ {
		pem += cert[i*64:(i+1)*64] + "\n"
	}
	if len(cert)%64 != 0 {
		pem += cert[chunks*64:] + "\n"
	}
	pem += "-----END CERTIFICATE-----"
	return pem
}
