# Azure Token Verification
A tiny go module for verifying access token and extracting the available claims if the token is valid using Azure v2 flow. Otherwise, package will throw error with proper error message.
The code does the following checks to determine if the token valid:
  1. Issuer Check
  2. Audience Check
  3. Token Expiration Check


## Installing
Run the following command to add this package to your project
```golang
go get github.com/cyberpunk-sh/azuretokenverification
```

## Example
### V2 Flow
```golang
package main

import (
	"fmt"

	"github.com/cyberpunk-sh/azuretokenverification"
)

func main() {
	accessToken := "<version 2 access token>"
	client_new := &azuretokenverification.Client{ClientID: "client_id", TenantID: "tenant_id", TokenVersion: "2.0"}
	claims, err := client_new.VerifyToken(accessToken)
	if err != nil {
		fmt.Printf("Failed to verify access token: %v\n", err)
	}

	// If token is valid, print the claims
	fmt.Printf("Token is valid. Claims: %+v\n", claims)

}
```

### V1 Flow
```golang
package main

import (
	"fmt"

	"github.com/cyberpunk-sh/azuretokenverification"
)

func main() {
	accessToken := "<version 1 access token>"
	client_new := &azuretokenverification.Client{ClientID: "api://client_id", TenantID: "tenant_id", TokenVersion: "1.0"}
	claims, err := client_new.VerifyToken(accessToken)
	if err != nil {
		fmt.Printf("Failed to verify access token: %v\n", err)
	}

	// If token is valid, print the claims
	fmt.Printf("Token is valid. Claims: %+v\n", claims)

}
```
## Support
For Feature suggestions and reporting Bugs, please raise an issue using [GitHub Issues](https://github.com/cyberpunk-sh/azuretokenverification/issues)

## License
Copyright (c) 2024 Premchand Chakkungal (https://cyberpunk.sh)

Licensed under [MIT License](./LICENSE)



