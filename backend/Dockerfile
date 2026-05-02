FROM zaproxy/zap-stable

USER root

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3.11-venv \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY main.py /app/main.py

RUN mkdir -p /app/scanner_outputs && chmod 777 /app/scanner_outputs

ENV PORT=8000

EXPOSE 8000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
