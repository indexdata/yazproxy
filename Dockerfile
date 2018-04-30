FROM natlibfi/usemarcon:v3

USER root
WORKDIR /app/build
CMD ["bin/yazproxy", "-c", "/conf/conf.xml", "@:8080"]

COPY . yazproxy/

RUN apk update
RUN apk add git g++ make automake autoconf libtool bison tcl-dev icu-dev gnutls-dev libxslt-dev libxml2-dev libgpg-error-dev libgcrypt-dev
RUN addgroup -S yaz
RUN adduser -S -h /app yaz yaz
RUN chown -R yaz:yaz /app

USER yaz

RUN git clone https://github.com/indexdata/yaz yaz
RUN git clone https://github.com/indexdata/yazpp yazpp

WORKDIR yaz
RUN ./buildconf.sh
RUN ./configure --prefix=/app
RUN make install-exec

WORKDIR ../yazpp
RUN ./buildconf.sh
RUN ./configure --prefix=/app
RUN make install-exec

WORKDIR ../yazproxy
RUN ./buildconf.sh
RUN ./configure --prefix=/app --with-usemarcon=/usemarcon
RUN make install-exec

WORKDIR /app

RUN rm -r build
USER root
RUN apk del git make automake autoconf libtool tcl-dev
USER yaz
