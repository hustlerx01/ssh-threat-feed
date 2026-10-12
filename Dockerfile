FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir stix2
ENTRYPOINT ["python", "-m", "sshfeed.cli"]
CMD ["--authlog", "data/OpenSSH_2k.log", "--cowrie", "tests/fixtures/cowrie.json", "-o", "results"]
