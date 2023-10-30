FROM golang:1.19

WORKDIR /app
COPY main.go go.mod go.sum trusted_setup.json /app/
RUN go build -o ./blob-me-maybe

EXPOSE 13337

ENTRYPOINT ["./blob-me-maybe"]
