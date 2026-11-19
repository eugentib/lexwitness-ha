ARG BUILD_FROM
FROM $BUILD_FROM
RUN apk add --no-cache python3 ca-certificates
COPY witness.py /witness.py
CMD ["python3", "-u", "/witness.py", "--config", "/data/options.json"]
