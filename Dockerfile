FROM python:3.11-slim

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

CMD ["sh", "-c", "gunicorn -w 2 -k gthread --threads 8 -b 0.0.0.0:${PORT:-8080} scp_gateway:app"]