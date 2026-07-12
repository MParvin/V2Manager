FROM python:3.12-slim

LABEL org.opencontainers.image.title="Xray Manager"
LABEL org.opencontainers.image.source="https://github.com/MParvin/V2Manager"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
