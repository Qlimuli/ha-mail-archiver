FROM s1t5/mailarchiver:latest

LABEL \
    io.hass.name="Mail Archiver" \
    io.hass.description="Lokales E-Mail-Archiv mit integriertem ClamAV-Virenschutz" \
    io.hass.type="addon" \
    io.hass.version="1.2.4" \
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
        clamav \
        clamav-daemon \
        clamav-freshclam \
        python3 \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/sbin/policy-rc.d \
    && nginx -V 2>&1 | grep -q http_sub_module || (echo "ERROR: ngx_http_sub_module missing" && exit 1) \
    && mkdir -p /var/run/clamav /var/lib/clamav /var/log/clamav \
    && chown -R clamav:clamav /var/run/clamav /var/lib/clamav /var/log/clamav \
    && sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf 2>/dev/null || true \
    && sed -i 's/^Example/#Example/' /etc/clamav/clamd.conf 2>/dev/null || true \
    && (grep -q '^LocalSocket' /etc/clamav/clamd.conf || echo 'LocalSocket /var/run/clamav/clamd.ctl' >> /etc/clamav/clamd.conf) \
    && (grep -q '^Foreground' /etc/clamav/clamd.conf || echo 'Foreground false' >> /etc/clamav/clamd.conf) \
    && chmod 755 /var/run/clamav

COPY rootfs/run.sh /run.sh
COPY rootfs/security.sh /security.sh
COPY rootfs/security_ui.py /security_ui.py
COPY rootfs/nginx.conf.template /nginx.conf.template
RUN chmod a+x /run.sh /security.sh /security_ui.py

ENTRYPOINT ["/bin/bash", "/run.sh"]
