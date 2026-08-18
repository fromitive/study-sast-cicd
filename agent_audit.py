"""
에이전트 로직 감사 패스
=====================

스캐너가 못 잡는 '로직/설계 결함'을 코드 추론으로 찾는다.
(예: 권한 검사 누락, 같은 기능인데 한쪽 함수만 검사, 신뢰 경계 착각 — 문법은 멀쩡함)

세 역할 (blackcon 파이프라인의 attack-surface / code-audit / verify 축약):
  recon    : 레포를 훑어 감사 우선순위 큐(고위험 파일 top-N)를 만든다
  auditor  : 파일마다 3단계로 추론
             1) 위협 후보 훑기
             2) 진짜 도달 가능한가 + 위에서 막는 검사(상위 게이트)가 있나
                + ★같은 파일 안에 '비대칭'이 있나 (한 함수는 검사, 형제 함수는 안 함)
             3) 살아남은 것만 finding으로 기록
  verifier : 전체 finding을 다시 보고 오탐 제거 + 심각도 확정

핵심 휴리스틱: 같은 액터·같은 신뢰 경계인데 한쪽에만 방어가 있으면
그건 설계 의도가 아니라 '누락'일 확률이 높다. (apple/container CVE-2026-64777의 결정적 단서)

탐지를 LLM이 한다는 점에서 sast.py(탐지=스캐너)와 반대 축. 둘을 합쳐야 완성된다.
사람은 마지막에 심각도 검증 + 익스플로잇 조립을 맡는다(자동화가 닫지 못하는 한 걸음).

⚠️ 본인이 감사 권한을 가진 코드에만 사용할 것.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

from harness import _call_llm            # 백엔드(cli/api) 재사용 → claude -p, 과금 없음
from sast import Finding, _parse_json, write_reports  # 공용 자료구조/리포터 재사용

AUDIT_MODEL = os.environ.get("AUDIT_MODEL", "sonnet")
TOP_N = int(os.environ.get("AGENT_TOP_N", "12"))
MAX_FILE_LINES = 1200                    # 파일이 크면 앞부분만 (컨텍스트 한계)

SRC_EXT = {".py", ".js", ".ts", ".go", ".java", ".swift", ".rb", ".php",
           ".c", ".cc", ".cpp", ".h", ".hpp", ".rs", ".cs", ".kt", ".scala"}
SKIP_DIR = {".git", "node_modules", "vendor", "dist", "build", "__pycache__", ".venv"}

# recon 사전 필터용 위험 키워드(싸게 후보를 좁힌다)
RISK_HINTS = [
    "auth", "login", "token", "session", "password", "secret", "permission",
    "admin", "role", "verify", "validate", "sign", "jwt", "crypt", "decrypt",
    "path", "file", "open", "read", "write", "symlink", "resolve", "redirect",
    "exec", "system", "subprocess", "popen", "eval", "deserial", "pickle",
    "unmarshal", "query", "sql", "request", "param", "input",
]


# ---------------------------------------------------------------------------
# 파일 수집 + 싼 사전 점수
# ---------------------------------------------------------------------------

def collect_files(root: str) -> list[tuple[pathlib.Path, int, int]]:
    """(경로, LOC, 위험키워드 히트수) 목록. 히트 0인 파일은 버린다."""
    out = []
    for p in pathlib.Path(root).rglob("*"):
        if not p.is_file() or p.suffix not in SRC_EXT:
            continue
        if any(part in SKIP_DIR for part in p.parts):
            continue
        try:
            text = p.read_text(errors="replace")
        except OSError:
            continue
        low = text.lower()
        hits = sum(low.count(k) for k in RISK_HINTS)
        if hits:
            out.append((p, text.count("\n") + 1, hits))
    out.sort(key=lambda x: x[2], reverse=True)
    return out


# ---------------------------------------------------------------------------
# recon — 감사 우선순위 큐
# ---------------------------------------------------------------------------

RECON_SYSTEM = """\
너는 코드베이스 정찰 담당이다. 후보 파일 목록(경로·LOC·위험키워드 히트수)을 보고,
보안 감사를 먼저 해야 할 고위험 파일을 우선순위대로 고른다.

우선순위 판단: 인증/인가, 외부입력 파싱, 경로/파일 처리, 역직렬화, 명령 실행,
신뢰 경계를 넘는 데이터 흐름에 닿을수록 높다.

반드시 아래 JSON만 출력한다(설명·백틱 금지):
{ "queue": [ { "file": "경로", "reason": "왜 위험한지 한 줄" }, ... ] }"""


def recon(candidates: list[tuple[pathlib.Path, int, int]], root: str, top_n: int) -> list[dict]:
    listing = [
        {"file": str(p.relative_to(root)), "loc": loc, "risk_hits": hits}
        for p, loc, hits in candidates[: top_n * 4]  # 후보를 넉넉히 주고 LLM이 추림
    ]
    user = (
        f"후보 {len(listing)}개 중 감사 우선순위 상위 {top_n}개를 큐로 만들어라.\n"
        + json.dumps(listing, ensure_ascii=False, indent=2)
    )
    try:
        return _parse_json(_call_llm(AUDIT_MODEL, RECON_SYSTEM, user, 2000))["queue"][:top_n]
    except (json.JSONDecodeError, KeyError, ValueError):
        # LLM 실패 시 키워드 점수 상위로 폴백
        return [{"file": str(p.relative_to(root)), "reason": "keyword score"}
                for p, _, _ in candidates[:top_n]]


# ---------------------------------------------------------------------------
# auditor — 파일별 3단계 추론
# ---------------------------------------------------------------------------

AUDITOR_SYSTEM = """\
너는 시니어 앱보안 감사자다. 주어진 소스 파일 한 개를 아래 3단계로 감사한다.

Stage 1 (위협 후보 훑기): 이 파일에 있을 수 있는 취약점 후보를 라인 참조와 함께 나열.
Stage 2 (걸러내기):
  - 진짜 외부 입력이 도달하는가? 상위에서 막는 검사(게이트)가 이미 있나? 있으면 후보 탈락.
  - ★비대칭 점검: 같은 파일에서 한 함수는 검사(경계/권한/입력)하는데
    형제 함수는 같은 검사를 빠뜨리지 않았나? 있으면 그건 '누락'일 확률이 높다 → 강한 후보.
  - 로직 결함(권한 검사 누락, IDOR, 신뢰 경계 착각, 검사 순서 오류)은 문법상 멀쩡해도 유효.
Stage 3 (기록): 살아남은 것만 finding으로 작성. 상위 게이트가 있어 무력화되면 verdict=FP.

반드시 아래 JSON만 출력한다(설명·백틱 금지):
{ "findings": [ {
    "category": "예: path-traversal / missing-authz / idor / trust-boundary",
    "title": "한 줄 요약",
    "start_line": 66,
    "severity": "critical|high|medium|low",
    "confidence": "high|medium|low",
    "verdict": "TP|FP",
    "reason": "근거 한 줄 (비대칭이면 어느 함수 대비 무엇이 빠졌는지 명시)",
    "fix": "수정 방향 한 줄"
  } ] }"""


def _numbered(text: str) -> str:
    lines = text.splitlines()[:MAX_FILE_LINES]
    return "\n".join(f"{i+1}: {ln}" for i, ln in enumerate(lines))


def audit_file(path: pathlib.Path, rel: str) -> list[Finding]:
    try:
        content = _numbered(path.read_text(errors="replace"))
    except OSError:
        return []
    user = f"파일: {rel}\n\n```\n{content}\n```\n\n3단계로 감사하고 findings JSON을 출력하라."
    try:
        parsed = _parse_json(_call_llm(AUDIT_MODEL, AUDITOR_SYSTEM, user, 2500))["findings"]
    except (json.JSONDecodeError, KeyError, ValueError):
        return []
    findings = []
    for f in parsed:
        findings.append(Finding(
            tool="agent-audit",
            rule_id=f.get("category", "logic"),
            file=rel,
            line=f.get("start_line", 0),
            severity=f.get("severity", "medium"),
            message=f.get("title", ""),
            is_true_positive=(f.get("verdict") != "FP"),
            business_severity=f.get("severity", "medium"),
            reason=f.get("reason", ""),
            fix=f.get("fix", ""),
        ))
    return findings


# ---------------------------------------------------------------------------
# verifier — 전체 finding 오탐 컷
# ---------------------------------------------------------------------------

VERIFIER_SYSTEM = """\
너는 감사 결과를 최종 검증하는 심판이다. 각 finding에 대해, 근거가 실제로
도달 가능하고 상위 게이트로 무력화되지 않는지 재검토한다. 과대평가된 심각도는 내린다.
이 서비스는 핀테크라 금융/개인정보/인증 경로는 심각도를 올린다.

반드시 아래 JSON만 출력한다:
{ "results": [ { "index": 0, "verdict": "TP|FP",
                 "severity": "critical|high|medium|low", "reason": "..." }, ... ] }"""


def verify(findings: list[Finding]) -> None:
    if not findings:
        return
    items = [
        {"index": i, "category": f.rule_id, "title": f.message,
         "file": f.file, "line": f.line, "severity": f.business_severity,
         "reason": f.reason}
        for i, f in enumerate(findings)
    ]
    user = "다음 finding들을 최종 검증하라:\n" + json.dumps(items, ensure_ascii=False, indent=2)
    try:
        results = _parse_json(_call_llm(AUDIT_MODEL, VERIFIER_SYSTEM, user, 2500))["results"]
    except (json.JSONDecodeError, KeyError, ValueError):
        print("  [warn] verify 파싱 실패 — auditor 판정 유지")
        return
    for r in results:
        f = findings[r["index"]]
        f.is_true_positive = (r.get("verdict") != "FP")
        f.business_severity = r.get("severity", f.business_severity)
        if r.get("reason"):
            f.reason = r["reason"]


# ---------------------------------------------------------------------------
# 오케스트레이션
# ---------------------------------------------------------------------------

def run_agent_audit(root: str, top_n: int = TOP_N) -> list[Finding]:
    print("  [recon] 파일 수집·우선순위 큐 생성...")
    candidates = collect_files(root)
    if not candidates:
        print("  감사할 소스 파일 없음.")
        return []
    queue = recon(candidates, root, top_n)
    print(f"  [recon] 큐 {len(queue)}개 확정")

    all_findings: list[Finding] = []
    for i, item in enumerate(queue, 1):
        rel = item["file"]
        path = pathlib.Path(root) / rel
        print(f"  [auditor {i}/{len(queue)}] {rel}")
        all_findings.extend(audit_file(path, rel))

    print(f"  [verifier] finding {len(all_findings)}개 검증...")
    verify(all_findings)
    return all_findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=".")
    ap.add_argument("--report", default="agent-report.json")
    ap.add_argument("--top", type=int, default=TOP_N)
    args = ap.parse_args()

    findings = run_agent_audit(args.target, args.top)
    if not findings:
        pathlib.Path(args.report).write_text("[]")
        return 0
    write_reports(findings, args.report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
