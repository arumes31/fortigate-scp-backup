FROM python:3.12-slim

RUN apt-get update && apt-get install -y tzdata freeradius-utils && pip install flask gunicorn apscheduler paramiko scp pytz pyotp pyrad setuptools psycopg2-binary sqlalchemy Flask-SQLAlchemy
#Debug
RUN apt install net-tools inetutils-ping
WORKDIR /app

COPY extensions/fgt_adm_vpn_conf /app/extensions/fgt_adm_vpn_conf
COPY . /app

RUN mkdir -p /app/data /app/backups /app/static && \
    cp logo.png /app/static/logo.png && \
    cp favicon.ico /app/static/favicon.ico && \
    chmod -R 777 /app/data /app/backups /app/static

RUN ulimit -n 4096

EXPOSE 8521

# Run with gunicorn in production.
# IMPORTANT: keep --workers at 1. The app runs an in-process APScheduler and a
# background Graylog/HookWise worker thread; multiple workers would each start
# their own, duplicating backups and Graylog lookups. Use threads (not workers)
# for request concurrency.
CMD ["gunicorn", "--workers", "1", "--threads", "8", "--timeout", "120", "--bind", "0.0.0.0:8521", "app:app"]