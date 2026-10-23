FROM s1t5/mailarchiver:latest

LABEL \
    io.hass.name="Mail Archiver" \
    io.hass.description="Lokales E-Mail-Archiv mit Weboberfläche für Home Assistant" \
    io.hass.type="addon" \
    io.hass.version="1.1.3" \
    maintainer="Home Assistant Community"

USER root

RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        jq \
        nginx-extras \
        postgresql \
        postgresql-client \
        tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/sbin/policy-rc.d

COPY rootfs/run.sh /run.sh
COPY rootfs/nginx.conf.template /nginx.conf.template
RUN chmod a+x /run.sh

ENTRYPOINT ["/bin/bash", "/run.sh"]
