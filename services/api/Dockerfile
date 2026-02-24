FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir \
    fastapi==0.109.0 \
    uvicorn[standard]==0.27.0 \
    python-multipart==0.0.6 \
    pydantic==2.5.3 \
    pydantic-settings==2.1.0 \
    sqlalchemy==2.0.25 \
    psycopg2-binary==2.9.9 \
    boto3==1.34.34 \
    redis==5.0.1 \
    prometheus-client==0.19.0

# Copy scarabeo package
COPY scarabeo /app/scarabeo

# Copy API service
COPY services/api /app/services/api

WORKDIR /app

EXPOSE 8000

CMD ["python", "-m", "services.api"]
