# Use a lightweight and secure base image
FROM python:3.9-slim

# Set working directory inside the container
WORKDIR /app

# Install system dependencies required for Python packages
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create user and group
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# Ensure /var/log directory exists and create the log file
RUN mkdir -p /app/logs && touch /app/logs/flask.log

# Change ownership to appuser and set appropriate permissions
RUN chown -R appuser:appgroup /app/logs && chmod -R 777 /app/logs

# Switch to the non-root user
USER appuser

# Expose the port dynamically
EXPOSE $APP_PORT

# Health check for container readiness
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -f http://localhost:$APP_PORT/health || exit 1

# Run the application with Gunicorn (4 workers for better concurrency)
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
