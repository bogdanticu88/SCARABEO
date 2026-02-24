FROM python:3.11-slim@sha256:1591aa8c01b5b37ab31dbe5662c5bdcf40c2f1bce4ef1c1fd24802dae3d01052

WORKDIR /app

# Install dependencies from locked requirements
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy scarabeo package
COPY scarabeo /app/scarabeo

# Copy orchestrator service
COPY services/orchestrator /app/services/orchestrator

WORKDIR /app

EXPOSE 8001

CMD ["python", "-m", "services.orchestrator"]
