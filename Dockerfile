FROM quay.io/natlibfi/usemarcon:3
ENTRYPOINT ["/yaz/entrypoint.sh"]

ENV PORT 10210
ENV CONF /conf/conf.xml

USER root

COPY . /build/yazproxy
COPY docker-entrypoint.sh /yaz/entrypoint.sh

WORKDIR /build

RUN apk -U --no-cache add libxslt libxml2 libgcrypt libgpg-error icu gnutls \
  && apk -U --no-cache add --virtual .build-deps g++ sudo git make automake \
    autoconf libtool bison tcl-dev icu-dev gnutls-dev libxslt-dev libxml2-dev \
    libgpg-error-dev libgcrypt-dev \
  && addgroup -S yaz && adduser -S -h /yaz yaz yaz \
  && chown -R yaz:yaz /build /yaz \
  && sudo -u yaz sh -c 'cd /build \
    && git clone https://github.com/indexdata/yaz && cd yaz \
    && ./buildconf.sh && ./configure --prefix=/yaz' \
  && sh -c 'cd yaz && make install-exec' \
  && sudo -u yaz sh -c 'cd /build \
    && git clone https://github.com/indexdata/yazpp && cd yazpp \
    && ./buildconf.sh && ./configure --prefix=/yaz' \
  && sh -c 'cd yazpp && make install-exec' \
  && sudo -u yaz sh -c 'cd /build/yazproxy && ./buildconf.sh \
    && ./configure --prefix=/yaz --with-usemarcon=/usemarcon' \
  && sh -c 'cd yazproxy && make install-exec && chown -R yaz:yaz /yaz' \
  && apk del .build-deps \
  && rm -rf /build tmp/* /var/cache/apk/*

WORKDIR /yaz
USER yaz