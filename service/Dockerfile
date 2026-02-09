FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY auth_service ./auth_service

EXPOSE 8081
CMD ["uvicorn", "auth_service.main:app", "--host", "0.0.0.0", "--port", "8081"]
