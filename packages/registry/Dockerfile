FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir . && useradd --create-home registry
USER registry
VOLUME /data
EXPOSE 8000
# First run: docker run --rm -v reg:/data IMAGE pregen-registry init --dir /data --prefix TEST --name "…" --api https://… --sandbox
CMD ["pregen-registry", "serve", "--dir", "/data", "--host", "0.0.0.0", "--port", "8000"]
