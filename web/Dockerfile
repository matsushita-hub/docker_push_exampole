FROM python:3.11-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN apt-get update && apt-get install -y gcc python3-dev \
    && pip wheel --no-cache-dir --wheel-dir /build/wheels -r requirements.txt


FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir /wheels/*
COPY . .
RUN mkdir -p /app/shared_uploads && chown -R 1000:1000 /app/shared_uploads
USER 1000
CMD gunicorn -w 4 -b 0.0.0.0:5000 app:app
