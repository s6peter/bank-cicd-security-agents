FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -o /season-worker .

FROM alpine:3.21
WORKDIR /app
COPY --from=build /season-worker /app/season-worker
CMD ["/app/season-worker"]
