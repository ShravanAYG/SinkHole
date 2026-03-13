FROM python:3.12-slim

# Set timezone and environmental variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BOTWALL_HOST=0.0.0.0 \
    BOTWALL_PORT=4000

WORKDIR /app

# Install dependencies first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire SinkHole engine
COPY botwall/ ./botwall/
COPY botwall.toml .

EXPOSE 4000

# Start Uvicorn via the module entrypoint
CMD ["python", "-m", "botwall"]
