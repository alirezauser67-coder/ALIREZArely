FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY main.py vless.py ws.py httpd.py links.py admin.py ./
CMD ["python", "main.py"]
