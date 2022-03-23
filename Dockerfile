FROM ghcr.io/linuxserver/baseimage-alpine:3.15 as builder

LABEL maintainer="Roxedus"

RUN \
  echo "**** install build packages ****" && \
  apk add \
    curl \
    git \
    go \
    make && \
  if [ -z ${BOUNCER_RELEASE+x} ]; then \
    BOUNCER_RELEASE=$(curl -sX GET https://api.github.com/repos/crowdsecurity/cs-custom-bouncer/releases/latest \
      | awk '/tag_name/{print $4;exit}' FS='[""]'); \
  fi && \
  mkdir -p \
    /buildout/app \
    /buildout/etc/crowdsec/bouncers && \
  git clone --depth 1 --branch ${BOUNCER_RELEASE} https://github.com/crowdsecurity/cs-custom-bouncer.git && \
  cd cs-custom-bouncer/ && \
  make build && \
  cp crowdsec-custom-bouncer /buildout/app/ && \
  cp config/crowdsec-custom-bouncer.yaml /buildout/etc/crowdsec/bouncers/

FROM ghcr.io/linuxserver/baseimage-alpine:3.15

LABEL maintainer="Roxedus"

ENV CROWDSEC_LAPI_URL=http://crowdsec:8080/ CROWDSEC_API_KEY=myaweseomekey
ENV UNIFI_IGNORE_SSL=true UNIFI_USERNAME=apiuser UNIFI_PASSWORD=changeme UNIFI_BASE_URL=https://unifi-controller:8443 UNIFI_SITE=default UNIFI_GROUP_ID=mygroup

RUN \
  apk add --no-cache \
    python3 \
    py3-requests \
    yq

COPY --from=builder /buildout /
COPY docker_root/ /
COPY unifi.py /app/unifi.py