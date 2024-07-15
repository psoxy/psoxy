FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y python3 python3-pip python-is-python3 gettext-base && \
    python -m pip install PyCryptodome PySocks flask requests

# Copy Psoxy files
COPY psoxy-client.py /app/psoxy-client.py
COPY psoxy-server.py /app/psoxy-server.py
COPY psoxy-relay.py /app/psoxy-relay.py
COPY psoxysocket.py /app/psoxysocket.py
COPY client.py /app/client.py
COPY server.py /app/server.py
COPY aes.py /app/aes.py
COPY config-template.py /app/config-template.py
COPY init.sh /app/init.sh

# Copy xray files
COPY _config.json.var /etc/_config.json.var
COPY entry.sh /entry.sh
COPY geoip.dat /usr/share/xray/geoip.dat
COPY geosite.dat /usr/share/xray/geosite.dat
COPY iran.dat /usr/share/xray/iran.dat
COPY xray /usr/bin/xray

WORKDIR /app

CMD [ "/app/init.sh" ]

