FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir flask requests gunicorn

EXPOSE 8080

CMD ["sh", "-c", "gunicorn -w 2 -k gthread --threads 8 -b 0.0.0.0:$PORT scp_gateway:app"]