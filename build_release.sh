CGO_ENABLED=1 go build -ldflags="-extldflags=-static -X main.Version=$(git describe --tags)" -tags sqlite_omit_load_extension,netgo,osusergo -o waygate
strip waygate
