package azuretokenverification

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWK struct {
	Kid string   `json:"kid"` // Key ID
	Kty string   `json:"kty"` // Key type (e.g., RSA)
	Alg string   `json:"alg"` // Algorithm (e.g., RS256)
	Use string   `json:"use"` // Usage (e.g., "sig" for signature)
	N   string   `json:"n"`   // Modulus (for RSA)
	E   string   `json:"e"`   // Exponent (for RSA)
	X5c []string `json:"x5c"` // Certificate chain
}

type Client struct {
	ClientID string // Client ID as a string
	TenantID string // Tenant ID as a string
}

func (c *Client) verify(accessToken string) (jwt.MapClaims, error) {
	jwksURL := fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", c.TenantID)

	// Fetch Microsoft's public key metadata (JWKS)
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	// Parse the JWKS
	var jwks struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	// Create a key function for verifying the token
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Ensure the token uses the RS256 signing method
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}

		// Find the correct key for the token using the "kid" in the header
		kid := token.Header["kid"]
		for _, key := range jwks.Keys {
			if key.Kid == kid {
				// Convert the key to an RSA public key and return it
				rsaKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(key.X5c[0]))
				if err != nil {
					return nil, fmt.Errorf("failed to parse public key: %w", err)
				}
				return rsaKey, nil
			}
		}

		return nil, fmt.Errorf("key not found for kid: %s", kid)
	}

	// Parse the access token
	token, err := jwt.ParseWithClaims(accessToken, &jwt.MapClaims{}, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Check if the token is valid
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	// Retrieve claims and verify issuer, audience, and expiration
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to cast claims to MapClaims")
	}
	expectedIssuer := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", c.TenantID)

	if claims["iss"] != expectedIssuer {
		return nil, fmt.Errorf("unexpected issuer: %s", claims["iss"])
	}

	if claims["aud"] != c.ClientID {
		return nil, fmt.Errorf("unexpected audience: %s", claims["aud"])
	}

	expiration := time.Unix(int64(claims["exp"].(float64)), 0)
	if time.Now().After(expiration) {
		return nil, fmt.Errorf("token is expired")
	}

	// Token is valid and verified
	return claims, nil
}
