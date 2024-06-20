FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y python3 python3-pip python-is-python3 && \
    python -m pip install PyCryptodome PySocks flask requests

COPY psoxy-client.py /app/psoxy-client.py
COPY psoxy-server.py /app/psoxy-server.py
COPY psoxy-relay.py /app/psoxy-relay.py
COPY client.py /app/client.py
COPY server.py /app/server.py
COPY aes.py /app/aes.py
COPY config-template.py /app/config-template.py
COPY init.sh /app/init.sh

WORKDIR /app

CMD [ "/app/init.sh" ]

