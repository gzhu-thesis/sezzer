FROM postgres:10-alpine

ARG version=2.0
ENV PGADMIN4_VERSION=$version
# Metadata
LABEL org.label-schema.name="pgAdmin4" \
      org.label-schema.version="$PGADMIN4_VERSION" \
      org.label-schema.license="PostgreSQL" \
      org.label-schema.url="https://www.pgadmin.org"

COPY pgadmin4-2.0-py2.py3-none-any.whl /

RUN set -ex && \
    apk update && \
    apk add --update --no-cache --virtual .run-deps \
                ca-certificates \
                openssl \
                python3-dev && \
    apk add --update --no-cache --virtual .build-deps \
                gcc \
                linux-headers \
                musl-dev && \
    pip3 --no-cache-dir install psutil /pgadmin4-2.0-py2.py3-none-any.whl && \
    apk del .build-deps

VOLUME /var/lib/pgadmin4

COPY pgadmin4.entrypoint /usr/local/bin/pgadmin4-entrypoint.sh
COPY start_service.sh /usr/local/bin/start_service.sh

ENTRYPOINT ["start_service.sh"]

EXPOSE 5050

CMD ["postgres", "pgadmin4"]
