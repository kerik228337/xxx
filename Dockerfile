FROM bash:5.3.3-alpine3.22
WORKDIR /app

RUN apk update && apk add jq sqlite postgresql-client
COPY ./server.sh ./server.sh
COPY ./static ./static

ENTRYPOINT [ "/usr/local/bin/bash", "/app/server.sh" ]

