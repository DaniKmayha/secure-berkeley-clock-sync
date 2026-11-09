# Multi-stage build: compile once, run the same binary in every container.
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/node ./cmd/node && \
    CGO_ENABLED=0 go build -o /out/keygen ./cmd/keygen

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/node /out/keygen /usr/local/bin/
COPY configs /configs
ENTRYPOINT ["/usr/local/bin/node"]
