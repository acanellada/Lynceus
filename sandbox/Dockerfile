FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# Lista cerrada de librerías de terceros que los servidores del benchmark
# pueden importar dentro del sandbox, cada una con versión exacta (nunca un
# rango). Instalar las dependencias propias de cada caso analizado queda
# fuera de alcance en v1: si un caso necesita una librería que no está aquí,
# hay que añadirla explícitamente a requirements.in, no instalarla
# dinámicamente. requirements.txt fija también las transitivas, cada una
# con su hash (--require-hashes), para que la imagen sea reproducible.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

RUN groupadd --gid 10001 sandbox \
    && useradd --uid 10001 --gid sandbox --no-create-home --shell /usr/sbin/nologin sandbox \
    && mkdir -p /case /harness

USER sandbox
WORKDIR /case
