FROM golang:1.10-alpine as builder

RUN apk add --no-cache make gcc musl-dev linux-headers

ADD . /go-caelum
RUN cd /go-caelum && make caelum

FROM alpine:latest

LABEL maintainer="etienne@go-caelum.com"

WORKDIR /go-caelum

COPY --from=builder /go-caelum/build/bin/caelum /usr/local/bin/caelum

RUN chmod +x /usr/local/bin/caelum

EXPOSE 8545
EXPOSE 30303

ENTRYPOINT ["/usr/local/bin/caelum"]

CMD ["--help"]
