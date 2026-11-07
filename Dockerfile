FROM python:3.10-slim AS recon-ng

RUN mkdir -p /recon-ng

WORKDIR /recon-ng

COPY ./REQUIREMENTS /recon-ng/REQUIREMENTS

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libxml2-dev libxslt-dev && \
    pip install --no-cache-dir -r REQUIREMENTS && \
    apt-get purge -y --auto-remove gcc && \
    rm -rf /var/lib/apt/lists/*
