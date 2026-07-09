# SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
# internal-tools Dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["python", "app.py"]
