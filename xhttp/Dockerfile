FROM python:3.13-slim
ARG XRAY_VERSION=26.10.10
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip \
 && curl -fsSL -o /tmp/xray.zip \
      "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" \
 && unzip -o /tmp/xray.zip -d /usr/local/bin xray \
 && chmod +x /usr/local/bin/xray \
 && apt-get purge -y curl unzip \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* /tmp/xray.zip
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY server.py ./
CMD ["python", "server.py"]
