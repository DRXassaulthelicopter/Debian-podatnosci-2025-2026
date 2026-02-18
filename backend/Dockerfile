FROM debian:trixie

ENV PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y \
        python3 \
        python3-requests \
        sshpass \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . /app

EXPOSE 8088

CMD ["python3", "main.py", "--listen", "0.0.0.0", "--port", "8088"]
