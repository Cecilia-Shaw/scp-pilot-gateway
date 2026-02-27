FROM python:3.11-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["sh","-c","gunicorn -w 2 -k gthread --threads 8 -b 0.0.0.0:$PORT --access-logfile - --error-logfile - scp_gateway:app"]