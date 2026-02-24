FROM python:3.11-slim
WORKDIR /analyzer
RUN pip install --no-cache-dir boto3==1.34.34
# YARA is optional - install if YARA_ENABLED=true
# RUN pip install yara-python==4.3.2
COPY analyzer.py .
COPY rules/ /analyzer/rules/
RUN mkdir -p /work/out/artifacts && useradd -m -u 1000 analyzer
USER analyzer
ENTRYPOINT ["python", "analyzer.py"]
