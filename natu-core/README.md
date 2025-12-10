# natu-core

## Build

Run the build at the module root so that all package files (including the modularized handlers) are compiled:

```
go build -o natu-core .
```

Building only `main.go` will fail because it omits supporting files such as `ssh_activity.go`. Use the command above (or `go build ./...`) to compile the complete server.
