FROM python:3-alpine3.6

ARG version=2.0
ENV PGADMIN4_VERSION=$version
# Metadata
LABEL org.label-schema.name="pgAdmin4" \
      org.label-schema.version="$PGADMIN4_VERSION" \
      org.label-schema.license="PostgreSQL" \
      org.label-schema.url="https://www.pgadmin.org"

COPY pgadmin4-2.0-py2.py3-none-any.whl /

RUN set -ex && \
    apk add --no-cache --virtual .run-deps \
                bash \
                postgresql \
                postgresql-libs && \
    apk add --no-cache --virtual .build-deps \
                gcc \
                musl-dev \
                openssl \
                postgresql-dev && \
    pip --no-cache-dir install /pgadmin4-2.0-py2.py3-none-any.whl&& \
    apk del .build-deps

VOLUME /var/lib/pgadmin4

COPY pgadmin4.entrypoint /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 5050
CMD ["pgadmin4"]

