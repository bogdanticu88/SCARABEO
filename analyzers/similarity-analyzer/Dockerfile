FROM python:3.11-slim
WORKDIR /analyzer
RUN pip install --no-cache-dir boto3==1.34.34
COPY analyzer.py .
RUN mkdir -p /work/out/artifacts && useradd -m -u 1000 analyzer
USER analyzer
ENTRYPOINT ["python", "analyzer.py"]
