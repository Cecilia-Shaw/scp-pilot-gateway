FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir flask gunicorn

# 关键：PORT 没有就用 5055；有就用 Railway 给的
CMD ["sh","-c","gunicorn -w 2 -k gthread --threads 8 -b 0.0.0.0:${PORT:-5055} scp_gateway:app"]