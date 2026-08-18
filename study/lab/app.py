"""
[실습용 취약 앱] — 일부러 취약하게 만든 코드. 절대 실제 서비스에 쓰지 말 것.
이 파일은 주로 Semgrep(SAST)이 잡는 '코드 패턴' 취약점을 담고 있다.
"""
import os
import subprocess
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # [취약1] shell=True + 사용자 입력 → 커맨드 인젝션
    #   ?host=127.0.0.1;rm -rf / 같은 입력이 그대로 쉘로 간다.
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    # [취약2] eval(사용자입력) → 임의 코드 실행
    return str(eval(expr))


@app.route("/user")
def get_user():
    user_id = request.args.get("id", "1")
    conn = sqlite3.connect("app.db")
    # [취약3] 문자열 포매팅 SQL → SQL 인젝션
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    return str(conn.execute(query).fetchall())


@app.route("/read")
def read_file():
    name = request.args.get("name", "readme.txt")
    # [취약4] 사용자 입력으로 경로 조합 → 경로 순회(Path Traversal)
    with open(os.path.join("/var/data", name)) as f:
        return f.read()


if __name__ == "__main__":
    # [취약5] 디버그 모드 + 0.0.0.0 바인딩 → 운영에서 위험
    app.run(host="0.0.0.0", debug=True)
