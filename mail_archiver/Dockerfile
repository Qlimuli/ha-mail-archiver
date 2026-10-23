FROM s1t5/mailarchiver:latest

LABEL \
    io.hass.name="Mail Archiver" \
    io.hass.description="Lokales E-Mail-Archiv mit Weboberfläche für Home Assistant" \
    io.hass.type="addon" \
    io.hass.version="1.1.5" \
    maintainer="Home Assistant Community"

USER root

RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        jq \
        nginx \
        postgresql \
        postgresql-client \
        tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/sbin/policy-rc.d \
    && nginx -V 2>&1 | grep -q http_sub_module || (echo "ERROR: ngx_http_sub_module missing" && exit 1)

COPY rootfs/run.sh /run.sh
COPY rootfs/nginx.conf.template /nginx.conf.template
RUN chmod a+x /run.sh

ENTRYPOINT ["/bin/bash", "/run.sh"]
