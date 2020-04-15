FROM alpine:3 as builder-dep

ARG YAZ_REF=master
ARG YAZPP_REF=master
ARG USEMARCON_REF=master

WORKDIR /build

RUN apk -U --no-cache add sudo git build-base automake autoconf libtool bison tcl-dev icu-dev gnutls-dev libxslt-dev libxml2-dev libgpg-error-dev libgcrypt-dev file \
  && git clone https://github.com/indexdata/yaz && cd yaz && git checkout $YAZ_REF \
  && ./buildconf.sh && ./configure --prefix=/yaz && make install-exec \
  && cd .. \
  && git clone https://github.com/indexdata/yazpp && cd yazpp && git checkout $YAZPP_REF \
  && ./buildconf.sh && ./configure --prefix=/yaz && make install-exec \
  && cd .. \
  && git clone https://github.com/indexdata/usemarcon && cd usemarcon && git checkout $USEMARCON_REF \
  && cd pcre && chmod +x CleanTxt config.guess config.sub configure depcomp Detrail install-sh perltest.pl PrepareRelease RunGrepTest RunTest 132html \
  && ./configure --enable-utf8 --enable-unicode-properties --disable-shared --disable-cpp && make \
  && cd .. \
  && ./buildconf.sh && ./configure --prefix=/yaz && make install-exec

FROM builder-dep as builder

COPY . /build/yazproxy

WORKDIR /build/yazproxy

RUN ./buildconf.sh && ./configure --prefix=/yaz --with-usemarcon=/yaz && make install-exec

FROM alpine:3
ENTRYPOINT ["/yaz/entrypoint.sh"]

ENV PORT 10210
ENV CONF /conf/conf.xml

COPY --from=builder /yaz /yaz
COPY docker-entrypoint.sh /yaz/entrypoint.sh

RUN apk -U --no-cache add libxslt libxml2 libgcrypt libgpg-error icu gnutls \
  && addgroup -S yaz \
  && adduser -S -h /yaz yaz yaz \
  && chown -R yaz:yaz /yaz

WORKDIR /yaz
USER yaz