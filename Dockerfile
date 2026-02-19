FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install flask requests

EXPOSE 5055

CMD ["python", "scp_gateway.py"]