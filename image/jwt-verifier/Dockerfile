FROM --platform=$BUILDPLATFORM golang:1.23.0-alpine AS build

WORKDIR /src

ARG TARGETOS
ARG TARGETARCH

COPY src/ .

COPY src/go.mod src/go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \ 
    go mod download

COPY src/*.go ./

RUN --mount=type=cache,target=/go/pkg/mod \ 
    CGO_ENABLED=0 GOOS=${TARGETOS} \ 
    GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o /out/main .

RUN go test

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/main /

EXPOSE 8080
ENTRYPOINT [ "/main" ]