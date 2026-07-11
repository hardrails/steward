FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' \
    -o /out/steward-executor ./cmd/steward-executor

FROM debian:bookworm-slim
COPY --from=build /out/steward-executor /usr/local/bin/steward-executor
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/steward-executor"]
