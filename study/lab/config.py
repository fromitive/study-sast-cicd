"""
[실습용 취약 앱] — 하드코딩된 비밀들. Gitleaks(시크릿 스캐너)가 잡는 대상.
실제라면 이건 전부 환경변수/시크릿 매니저로 빼야 한다.
"""

# [시크릿1] AWS 액세스 키 (형태만 진짜, 실제로는 무효인 예제 키)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# [시크릿2] 하드코딩된 DB 비밀번호
DATABASE_URL = "postgres://admin:SuperSecretP@ssw0rd@db.internal:5432/prod"

# [시크릿3] 프라이빗 API 토큰 형태
STRIPE_SECRET_KEY = "sk_live_51H8xIamFakeButLooksRealABCDEFGHIJKLMNOP"

# [시크릿4] 일반 API 키
SLACK_WEBHOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
