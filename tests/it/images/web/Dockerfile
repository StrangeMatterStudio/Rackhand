# A web service for the check tests (plan T46): HTTP on 8080 and HTTPS on 8443, two processes so one can stop alone.
# The HTTPS certificate is the test's, mounted at /certs.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 procps && rm -rf /var/lib/apt/lists/*
COPY serve.py /serve.py
CMD ["sh", "-c", "python3 /serve.py web & python3 /serve.py tls & wait"]
