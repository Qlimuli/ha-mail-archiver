FROM s1t5/mailarchiver:latest

LABEL \
    io.hass.name="Mail Archiver" \
    io.hass.description="Lokales E-Mail-Archiv mit Weboberfläche für Home Assistant" \
    io.hass.type="addon" \
    io.hass.version="1.0.0" \
    maintainer="Home Assistant Community"

# Copy run script
COPY rootfs/run.sh /run.sh
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
