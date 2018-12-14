FROM golang:alpine as builder

RUN apk --no-cache add git gcc musl-dev binutils

RUN mkdir /build

ADD . /build/

WORKDIR /build

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o protoc-sdk . \
    && strip protoc-sdk

FROM carno/protoc-assets as assets

FROM alpine

RUN apk --no-cache add ca-certificates protobuf

COPY --from=assets /build/protoc-gen /usr/bin
COPY --from=builder /build/protoc-sdk /usr/bin

ENTRYPOINT ["/usr/bin/protoc-sdk"]
