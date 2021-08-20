FROM golang:alpine as builder

RUN apk update ; apk add -U --no-cache tzdata bash upx ca-certificates

ARG PKG=pki 
ARG GITLAB_TOKEN

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

COPY go.mod ./
COPY go.sum ./
RUN go mod download
COPY *.go ./
COPY ./templates  /go/bin/$PKG
ENV CGO_ENABLED=0
RUN go build -o /go/bin/$PKG

# go get uses git to pull lib dependencies
# RUN git config --global url."https://oauth2:$GITLAB_TOKEN@gitlab.com".insteadOf "https://gitlab.com"

# RUN env GO111MODULE=on GOPRIVATE=gitlab.com go get ./...
# RUN go get -u github.com/ahmetb/govvv
# RUN CGO_ENABLED=0 govvv build -a -installsuffix cgo -ldflags " -s -w" -o /go/bin/$PKG main.go

# RUN upx /go/bin/$PKG

FROM scratch

WORKDIR /

# EXPOSE 6666
EXPOSE 6666
USER 1001

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder --chown=1001 /go/bin/$PKG /$PKG
COPY --from=builder --chown=1001 /go/bin/certs/clients /certs/clients

#COPY --from=builder /go/src/app/static /static

ENTRYPOINT ["/pki"]
