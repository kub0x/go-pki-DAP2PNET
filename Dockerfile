FROM golang:alpine as builder

RUN apk update ; apk add -U --no-cache tzdata bash ca-certificates

ARG PKG=pki 
ARG CA
ARG CA_KEY
ARG CERTIFICATE
ARG PRIVATE_KEY 

RUN apk update \
 && apk add git

RUN mkdir -p /go/src \
 && mkdir -p /go/bin \
 && mkdir -p /go/pkg

ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH

RUN mkdir -p $GOPATH/src/app
ADD . $GOPATH/src/app

WORKDIR $GOPATH/src/app

RUN mkdir -p /go/bin/certs/clients

RUN echo "$CA" | tee /go/bin/certs/ca.pem
RUN echo "$CA_KEY" | tee /go/bin/certs/ca.key
RUN echo "$CERTIFICATE" | tee /go/bin/certs/pki.dap2p.net.pem
RUN echo "$PRIVATE_KEY" | tee /go/bin/certs/pki.dap2p.net.key

RUN mv ./templates /go/bin/

COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY *.go ./

ENV CGO_ENABLED=0
RUN go build -o /go/bin/$PKG

FROM scratch

WORKDIR /

EXPOSE 6666
USER 1001

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder --chown=1001 /go/bin/$PKG ./$PKG
COPY --from=builder --chown=1001 /go/bin/certs/ ./certs

#COPY --from=builder /go/src/app/static /static

ENTRYPOINT ["./pki"]
