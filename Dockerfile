FROM python:3.12-alpine
WORKDIR /app
COPY app/service.py /app/service.py
COPY app/traffic.py /app/traffic.py
CMD ["python","/app/service.py"]
