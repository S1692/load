# 1. Base Image
FROM python:3.11-slim

# 2. Set Environment Variables
# - PYTHONUNBUFFERED: Ensures that Python output is sent straight to the terminal without being buffered first.
# - PYTHONDONTWRITEBYTECODE: Prevents Python from writing .pyc files to disc.
# - WORKDIR: The working directory inside the container.
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
ENV WORKDIR /app
WORKDIR $WORKDIR

# 3. Install Dependencies
# - First, copy only the requirements file to leverage Docker's cache.
# - Install dependencies using pip.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# 4. Copy Application Code
# Copy the application source code and data into the container.
COPY ./app ./app
COPY ./data ./data

# 5. Expose Port
# Expose the port the app runs on. I decided on 8001 for this service.
EXPOSE 8001

# 6. Run Application
# Use Gunicorn, a production-ready WSGI server.
# -w 4: Use 4 worker processes.
# -k uvicorn.workers.UvicornWorker: Use Uvicorn workers for ASGI compatibility.
# -b 0.0.0.0:8001: Bind to all network interfaces on port 8001.
CMD ["gunicorn", "-w", "2", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8001", "app.main:app"]
