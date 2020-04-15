FROM alpine:3 as builder-dep

WORKDIR /build

RUN apk -U --no-cache add g++ sudo git make automake autoconf libtool bison tcl-dev icu-dev gnutls-dev libxslt-dev libxml2-dev libgpg-error-dev libgcrypt-dev file \
  && git clone https://github.com/indexdata/yaz && cd yaz \
  && ./buildconf.sh && ./configure --prefix=/yaz && make install-exec \
  && cd /build \
  && git clone https://github.com/indexdata/yazpp && cd yazpp \
  && ./buildconf.sh && ./configure --prefix=/yaz && make install-exec

FROM builder-dep as builder

COPY . /build/yazproxy

WORKDIR /build/yazproxy

RUN ./buildconf.sh && ./configure --prefix=/yaz --with-usemarcon=/usemarcon && make install-exec

FROM alpine:3
ENTRYPOINT ["/yaz/entrypoint.sh"]

ENV PORT 10210
ENV CONF /conf/conf.xml

COPY --from=builder /yaz /yaz
COPY --from=quay.io/natlibfi/usemarcon:3 /usemarcon /usemarcon
COPY docker-entrypoint.sh /yaz/entrypoint.sh

RUN apk -U --no-cache add libxslt libxml2 libgcrypt libgpg-error icu gnutls \
  && addgroup -S yaz \
  && adduser -S -h /yaz yaz yaz \
  && chown -R yaz:yaz /yaz

WORKDIR /yaz
USER yaz