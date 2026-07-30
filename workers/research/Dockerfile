FROM python:3.13-slim-bookworm@sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/usr/local/bin:/usr/bin:/bin

RUN printf '%s\n' \
      'pypdf==6.14.2 --hash=sha256:3f07891af76dc002657e04993ab9b4de81de29f9013b9761d0b7968bff12e946' \
      >/tmp/research-requirements.txt \
    && python3 -m pip install \
      --disable-pip-version-check \
      --no-cache-dir \
      --no-deps \
      --only-binary=:all: \
      --require-hashes \
      --requirement /tmp/research-requirements.txt \
    && rm -f /tmp/research-requirements.txt

COPY --chown=0:0 --chmod=0555 research_worker.py /opt/steward/research_worker.py

USER 65532:65532
WORKDIR /nonexistent
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/python3", "-I", "/opt/steward/research_worker.py"]
