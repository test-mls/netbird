FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Listen on all interfaces inside the container only. Do not publish the port:
# only the NetBird proxy (through a NetBird peer on the same private network)
# should reach this app.
ENV HOST=0.0.0.0 PYTHONUNBUFFERED=1
USER 65534
EXPOSE 8002
CMD ["python", "server.py"]
