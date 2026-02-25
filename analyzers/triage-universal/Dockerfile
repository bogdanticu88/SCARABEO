# Build context must be the project root:
#   docker build -t scarabeo/triage-universal:latest \
#     -f analyzers/triage-universal/Dockerfile .
FROM python:3.11-slim@sha256:1591aa8c01b5b37ab31dbe5662c5bdcf40c2f1bce4ef1c1fd24802dae3d01052

WORKDIR /analyzer

RUN pip install --no-cache-dir boto3==1.34.34

# Copy shared libraries so the analyzer can import them locally
COPY scarabeo/ioc.py ioc.py
COPY scarabeo/evasion.py evasion.py

COPY analyzers/triage-universal/analyzer.py .

RUN mkdir -p /work/output/artifacts

RUN useradd -m -u 1000 analyzer
USER analyzer

ENTRYPOINT ["python", "analyzer.py"]
