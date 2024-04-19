# Azure Token Verification
A tiny go module for verifying access token and extracting the available claims if the token is valid. Otherwise, package will throw error with proper error message.

## Installing
Run the following command to add this package to your project
```
go get github.com/cyberpunk-sh/azuretokenverification

```

## Example
```
package main

import (
	"github.com/cyberpunk-sh/azuretokenverification"
)

func main() {
	accessToken := ""
	client_new := &azuretokenverification.Client{ClientID: "test", TenantID: "test"}
	claims, err := client_new.VerifyToken(accessToken)

}

```

## License
Copyright (c) 2024 Premchand Chakkungal (https://cyberpunk.sh)

Licensed under [MIT License](./LICENSE)



