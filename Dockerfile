FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY phishdetect ./phishdetect
COPY server ./server

# Run as an unprivileged user; only /data is writable.
RUN useradd --system --uid 10001 app && mkdir /data && chown app /data
USER app
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')"
CMD ["uvicorn", "server.app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
