FROM golang:alpine as builder

RUN apk --no-cache add git gcc musl-dev binutils

RUN mkdir /build

ADD . /build/

WORKDIR /build

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o protoc-sdk . \
    && strip protoc-sdk

FROM carno/protoc-gen as assets

FROM alpine

RUN apk --no-cache add ca-certificates libc6-compat

COPY --from=builder /build/protoc-sdk /usr/local/bin
COPY --from=assets /usr/local/bin/protoc-gen /usr/local/bin

COPY --from=assets /usr/local/bin/protoc /usr/local/bin/protoc
COPY --from=assets /usr/local/include/google /usr/local/include/google

ENTRYPOINT ["protoc-sdk"]
