# [실습용] Trivy가 이미지/설정(misconfig)을 잡는 대상.
# 일부러 오래된 베이스 이미지 + root 실행 등 나쁜 관행을 넣었다.
FROM python:3.9-slim

# [misconfig] root로 실행 (USER 지정 없음)
WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt

# [misconfig] 시크릿을 빌드 인자/환경변수로 (이미지에 박힘)
ENV AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

EXPOSE 5000
CMD ["python", "app.py"]
