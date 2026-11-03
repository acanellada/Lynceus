FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Misma base (digest) que sandbox/Dockerfile y la misma versión de uv que fija
# .github/workflows/ci.yml: una sola fuente de verdad para "qué uv usamos".
# requirements.txt fija también el hash de cada fichero subido a PyPI para
# esta versión (--generate-hashes), igual que sandbox/requirements.txt.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

RUN groupadd --gid 10001 sandbox \
    && useradd --uid 10001 --gid sandbox --no-create-home --shell /usr/sbin/nologin sandbox

USER sandbox
