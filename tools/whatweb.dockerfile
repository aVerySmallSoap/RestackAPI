# Docker image by guikcd
# https://github.com/guikcd/docker-whatweb/blob/master/0.5.5-alpine/Dockerfile
FROM ruby:2.7-alpine AS builder

ENV WHATWEB_VERSION v0.5.5

RUN apk --no-cache add git make gcc musl-dev sudo
RUN git clone --branch "$WHATWEB_VERSION" https://github.com/urbanadventurer/WhatWeb.git /src/whatweb

# https://github.com/urbanadventurer/WhatWeb/wiki/Installation
RUN gem install rchardet:1.8.0 mongo:2.14.0 json:2.5.1

WORKDIR /src/whatweb
RUN bundle install

FROM ruby:2.7-alpine

COPY --from=builder /usr/local/bundle/ /usr/local/bundle/
COPY --from=builder /src/whatweb /src/whatweb/

WORKDIR /src/whatweb

CMD /src/whatweb/whatweb