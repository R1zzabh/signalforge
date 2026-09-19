FROM python:3.12-slim
WORKDIR /opt/lab
COPY lab/target /opt/lab/target
COPY lab/attacker /opt/lab/attacker
COPY lab/telemetry /opt/lab/telemetry
COPY lab/controller /opt/lab/controller
COPY lab/c2 /opt/lab/c2
ENV PYTHONUNBUFFERED=1
