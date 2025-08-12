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
COPY ./data ./data

# 5. Expose Port
# This is the internal port for the chatbot service
EXPOSE 8001

# 6. Run Application
# Use Gunicorn with Uvicorn workers for the ASGI app.
# Port 8001 is used internally within the Docker network.
CMD ["gunicorn", "-w", "2", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8001", "app.main:app"]
