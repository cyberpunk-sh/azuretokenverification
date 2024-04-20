package azuretokenverification

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Client struct {
	ClientID string // Client ID as a string
	TenantID string // Tenant ID as a string
}

// Fetch JWKS data from the URL and parse it into a JWKS struct
func fetchJWKS(url string) (*JWKS, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	return &jwks, nil
}

// Use this method to Verify Access Token
// Returns Claims if token is valid else returns error
func (c *Client) VerifyToken(accessToken string) (*jwt.MapClaims, error) {
	// Define the JWKS URL (e.g., for Azure AD)
	jwksURL := fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", c.TenantID)

	// Fetch and parse the JWKS data
	jwks, err := fetchJWKS(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Ensure the token uses the RS256 signing method
		if token.Method.Alg() != jwt.SigningMethodRS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}

		// Find the correct key for the token using the "kid" in the header
		kid := token.Header["kid"]
		for _, key := range jwks.Keys {
			if key.Kid == kid {
				decodedCert := DecodePEM(key.X5c[0])
				// Parse the RSA public key from the PEM-encoded certificate
				rsaKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(decodedCert))
				if err == nil {
					return rsaKey, nil
				}
			}
		}
		return nil, fmt.Errorf("key not found for kid: %s", kid)

	}

	token, err := jwt.ParseWithClaims(accessToken, &jwt.MapClaims{}, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Check if the token is valid
	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	// Retrieve claims and verify issuer, audience, and expiration
	claims, ok := token.Claims.(*jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("failed to cast claims to MapClaims")
	}
	expectedIssuer := fmt.Sprintf("https://sts.windows.net/%s/", c.TenantID)

	issuer, _ := claims.GetIssuer()
	if issuer != expectedIssuer {
		return nil, fmt.Errorf("unexpected issuer: %s", issuer)
	}

	audiances, _ := claims.GetAudience()
	if !isAudiance(audiances, c.ClientID) {
		return nil, fmt.Errorf("unexpected audience: %s", audiances)
	}

	raw_expiration, _ := claims.GetExpirationTime()
	if time.Now().After(raw_expiration.Time) {
		return nil, fmt.Errorf("token is expired")
	}

	// Token is valid and verified
	return claims, nil
}

func isAudiance(audiances jwt.ClaimStrings, client_id string) bool {
	for _, audience := range audiances {
		if audience == client_id {
			return true
		}
	}
	return false
}
