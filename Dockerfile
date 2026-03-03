FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Railway uses $PORT
CMD ["sh", "-c", "gunicorn -w 2 -k gthread -t 60 -b 0.0.0.0:${PORT:-8080} scp_gateway:app"]