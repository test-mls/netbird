FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY devkeys.py fake_proxy.py mint_token.py try_mcp.py ./
ENV PYTHONUNBUFFERED=1 NETBIRD_DEV_KEY_DIR=/keys
ENTRYPOINT ["python", "fake_proxy.py"]
