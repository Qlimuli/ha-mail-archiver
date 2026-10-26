FROM s1t5/mailarchiver:latest

LABEL \
    io.hass.name="Mail Archiver" \
    io.hass.description="Lokales E-Mail-Archiv mit integriertem ClamAV-Virenschutz" \
    io.hass.type="addon" \
    io.hass.version="1.3.30" \
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
COPY rootfs/security_ui_app.py /security_ui_app.py
COPY rootfs/security_ui.html /security_ui.html
COPY rootfs/mail_rules.py /mail_rules.py
COPY rootfs/mail_rules_part00.b64 /mail_rules_part00.b64
COPY rootfs/mail_rules_part01.b64 /mail_rules_part01.b64
COPY rootfs/mail_rules_part02.b64 /mail_rules_part02.b64
COPY rootfs/mail_rules_part03.b64 /mail_rules_part03.b64
COPY rootfs/mail_rules_part04.b64 /mail_rules_part04.b64
COPY rootfs/mail_rules_part05.b64 /mail_rules_part05.b64
COPY rootfs/mail_rules_part06.b64 /mail_rules_part06.b64
COPY rootfs/mail_rules_part07.b64 /mail_rules_part07.b64
COPY rootfs/mail_rules_part08.b64 /mail_rules_part08.b64
COPY rootfs/mail_rules_part09.b64 /mail_rules_part09.b64
COPY rootfs/db_virus_scan.py /db_virus_scan.py
COPY rootfs/nginx.conf.template /nginx.conf.template
COPY rootfs/ha-ui-inject.js /ha-ui-inject.js
RUN chmod a+x /run.sh /security.sh /security_ui.py /db_virus_scan.py

ENTRYPOINT ["/bin/bash", "/run.sh"]
