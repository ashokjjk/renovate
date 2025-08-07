FROM --platform=$BUILDPLATFORM golang:1.22.2-alpine@sha256:cdc86d9f363e8786845bea2040312b4efa321b828acdeb26f393faa864d887b0 AS builder

WORKDIR /build

ARG TARGETOS
ARG TARGETARCH

COPY src/go.mod src/go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \ 
    go mod download

COPY src/*.go ./
COPY mime.types /etc/mime.types

RUN go test

RUN --mount=type=cache,target=/go/pkg/mod \ 
    CGO_ENABLED=0 GOOS=${TARGETOS} \ 
    GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o app .

FROM gcr.io/distroless/static-debian12:nonroot@sha256:cdf4daaf154e3e27cfffc799c16f343a384228f38646928a1513d925f473cb46

WORKDIR /bin/

COPY --from=builder --chown=nonroot:nonroot /build/app .
COPY --from=builder --chown=nonroot:nonroot /etc/mime.types /etc/mime.types

EXPOSE 8080
ENTRYPOINT ["./app"]
