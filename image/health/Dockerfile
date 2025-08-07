FROM --platform=$BUILDPLATFORM golang:1.23.0-alpine@sha256:d0b31558e6b3e4cc59f6011d79905835108c919143ebecc58f35965bf79948f4 AS builder

WORKDIR /build

ARG TARGETOS
ARG TARGETARCH

COPY src/go.mod src/go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \ 
    go mod download

COPY src/*.go ./

RUN go test

RUN --mount=type=cache,target=/go/pkg/mod \ 
    CGO_ENABLED=0 GOOS=${TARGETOS} \ 
    GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o app .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:cdf4daaf154e3e27cfffc799c16f343a384228f38646928a1513d925f473cb46

WORKDIR /bin/

COPY --from=builder --chown=nonroot:nonroot /build/app .

EXPOSE 8080
ENTRYPOINT ["./app"]
