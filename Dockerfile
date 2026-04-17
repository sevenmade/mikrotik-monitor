FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src /app/src
COPY config /app/config

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import pathlib, time; p=pathlib.Path('/tmp/mikrotik_monitor.heartbeat'); print('ok' if p.exists() and time.time()-float(p.read_text())<180 else (_ for _ in ()).throw(SystemExit(1)))"

CMD ["python", "-m", "src.app"]
