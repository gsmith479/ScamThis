FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TLDEXTRACT_CACHE=/tmp/tldextract \
    DATA_DIR=/data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot/ ./bot/

# Run as the host user's UID so ./data stays editable from the host
ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} app && useradd -u ${UID} -g ${GID} -M -s /usr/sbin/nologin app \
    && mkdir -p /data && chown app:app /data
USER app

CMD ["python", "-m", "bot.main"]
