FROM golang:1.26.1@sha256:595c7847cff97c9a9e76f015083c481d26078f961c9c8dca3923132f51fe12f1

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download && go mod verify

ENV GOCACHE=/root/.cache/go-build

COPY . .
RUN go build -v -o /waf ./cmd/coraza-envoy-extproc

CMD ["/waf"]