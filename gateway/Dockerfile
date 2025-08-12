# 1. Base Image
FROM python:3.11-slim

# 2. Set Environment Variables
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
ENV WORKDIR /app
WORKDIR $WORKDIR

# 3. Install Dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 4. Copy Application Code
COPY ./app ./app

# 5. Expose Port
# I decided on 8000 for the gateway service.
# This is the internal port within the Docker network.
EXPOSE 8000

# 6. Run Application
# Use Gunicorn with Uvicorn workers for the ASGI app.
# The LLM_SERVICE_URL will be provided by docker-compose.
CMD ["gunicorn", "-w", "2", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8000", "app.main:app"]
