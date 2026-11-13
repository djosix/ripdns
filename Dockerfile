# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/ripdns .

FROM scratch
COPY --from=build /out/ripdns /ripdns
USER 65534:65534
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/ripdns"]
