FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN set -eux; \
    pip install --no-cache-dir --retries 8 --timeout 60 -r requirements.txt \
 || pip install --no-cache-dir -i https://mirror.kakao.com/pypi/simple --retries 8 --timeout 60 -r requirements.txt
COPY http_script.py /app/http_script.py
ENV TZ=Asia/Seoul
EXPOSE 8080

