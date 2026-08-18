"""데모용 취약 샘플. semgrep --config auto 가 잡을 만한 패턴 몇 개."""
import os
import subprocess

AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"  # 하드코딩 시크릿 (gitleaks/trivy)


def run(cmd):
    # shell=True + 사용자 입력 → 커맨드 인젝션 (semgrep)
    return subprocess.call(cmd, shell=True)


def calc(expr):
    return eval(expr)  # eval on input → 코드 인젝션 (semgrep)


def get_user(db, user_id):
    # 문자열 포매팅 SQL → SQL 인젝션 (semgrep)
    return db.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
