# gaef-user-service

Users service for Groups and Encounters Finder.
Authenticates, stores and retrieves users.

## Running

Provide a .env file in the repo root with the necessary environment variables (see [](main.go)).

Run a mongoDB instance with, for example:

```
docker run --name users-mongo -d -p 27017:27017 mongo
```

Run the server:

```
go fmt ./...
go vet ./...
go test ./...
go build . 
./gaef-user-service --production=true
```
Or simply 

```
go run .
```

