# Multi-stage build for tsmetrics
FROM golang:1.24-alpine AS build
WORKDIR /src
# Enable Go modules & download deps first (better layer caching)
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Build statically (no CGO needed)
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/tsmetrics .

FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /app
COPY --from=build /out/tsmetrics /app/tsmetrics
EXPOSE 9100
USER nonroot:nonroot
ENTRYPOINT ["/app/tsmetrics"]
