FROM python:3.12-slim

RUN apt-get update && apt-get install -y tzdata freeradius-utils && pip install flask apscheduler paramiko scp pytz pyotp pyrad setuptools psycopg2-binary sqlalchemy
#Debug
RUN apt install net-tools
WORKDIR /app

COPY . /app

RUN mkdir -p /app/data /app/backups /app/static && \
    cp logo.png /app/static/logo.png && \
    cp favicon.ico /app/static/favicon.ico && \
    chmod -R 777 /app/data /app/backups /app/static

RUN ulimit -n 4096

EXPOSE 8521

CMD ["python", "app.py"]