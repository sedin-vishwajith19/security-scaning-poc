# INTENTIONALLY INSECURE Dockerfile for the KICS POC demo.
# Every line below should trigger a finding. All values are fake.

# Uses :latest (unpinned)
FROM python:latest

# Hardcoded secret in ENV -> should FAIL the build
ENV DB_PASSWORD=Sup3rS3cretValue99

# sudo, no --no-install-recommends, apt lists not deleted, versions not pinned
RUN apt-get update && apt-get install -y curl sudo

# ADD with a remote URL instead of COPY
ADD https://example.com/tools/app-tool.tar.gz /opt/

# pip without --no-cache-dir and without pinned version
RUN pip install flask

WORKDIR /app
COPY . .

# Exposing SSH
EXPOSE 22

# No USER instruction -> container runs as root
# No HEALTHCHECK
CMD python app.py
