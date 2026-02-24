FROM python:3.11-slim@sha256:1591aa8c01b5b37ab31dbe5662c5bdcf40c2f1bce4ef1c1fd24802dae3d01052

WORKDIR /app

# Install minimal dependencies
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir \
    fastapi==0.109.0 \
    uvicorn==0.27.0 \
    jinja2==3.1.2 \
    requests==2.31.0 \
    pydantic==2.5.3 \
    pydantic-settings==2.1.0

# Copy scarabeo package
COPY scarabeo /app/scarabeo

# Copy web service
COPY services/web /app/services/web

WORKDIR /app

EXPOSE 8080

CMD ["python", "-m", "services.web"]
