# Official multi-arch image (amd64, arm64, arm/v7, arm/v6, 386); recent Supervisors give no default BUILD_FROM.
FROM python:3.12-alpine
COPY witness.py /witness.py
CMD ["python3", "-u", "/witness.py", "--config", "/data/options.json"]
