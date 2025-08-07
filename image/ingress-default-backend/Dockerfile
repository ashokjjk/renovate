FROM --platform=$BUILDPLATFORM golang:1.22.2-alpine AS builder

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

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /bin/

COPY --from=builder --chown=nonroot:nonroot /build/app .
COPY --from=builder --chown=nonroot:nonroot /etc/mime.types /etc/mime.types

EXPOSE 8080
ENTRYPOINT ["./app"]
