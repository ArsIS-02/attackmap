FROM docker.io/library/python:3.13-alpine
WORKDIR /app
COPY app.py index.html ./
ENV AM_PORT=8097
EXPOSE 8097
CMD ["python3", "app.py"]
