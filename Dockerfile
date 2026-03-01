FROM python:3.11-slim

WORKDIR /app

# install deps first (better caching)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# copy app
COPY . .

# Railway provides $PORT. Fallback to 8080 locally.
CMD ["sh", "-c", "gunicorn -w 2 -k gthread --threads 8 -b 0.0.0.0:${PORT:-8080} scp_gateway:app"]