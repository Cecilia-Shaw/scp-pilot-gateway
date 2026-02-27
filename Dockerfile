FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir flask requests gunicorn

EXPOSE 5055

CMD ["gunicorn", "-w", "2", "-k", "gthread", "--threads", "8", "-b", "0.0.0.0:5055", "scp_gateway:app"]