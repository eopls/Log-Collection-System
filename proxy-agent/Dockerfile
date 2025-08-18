FROM python:3.11-slim
WORKDIR /app

COPY proxy-agent/requirements.txt .
RUN set -eux; \
    pip install --no-cache-dir --retries 8 --timeout 60 -r requirements.txt \
 || pip install --no-cache-dir -i https://mirror.kakao.com/pypi/simple --retries 8 --timeout 60 -r requirements.txt

COPY http-agent/http_script.py  /app/http_script.py
COPY email-agent/email_script.py /app/email_script.py

ENV TZ=Asia/Seoul
EXPOSE 8080
VOLUME ["/root/.mitmproxy"]

CMD ["mitmdump", "-p", "8080", "-s", "/app/http_script.py", "-s", "/app/email_script.py"]

