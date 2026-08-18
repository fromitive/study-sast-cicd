"""
SAST 트리아지 에이전트
=====================

탐지는 결정론적 스캐너, 판단은 LLM.

  Semgrep / Trivy / Gitleaks  ──► 정규화 ──► dedup ──► LLM 트리아지 ──► 통합 리포트
       (탐지·재현 가능)                              (claude -p: 오탐판별·
                                                     심각도 재랭킹·패치 제안)

하네스의 _call_llm(백엔드 cli/api 스위치)을 그대로 재사용 → SAST도 과금 없이 돌아감.

사용법:
    python sast.py --target ./myrepo --report sast-report.json

⚠️  본인이 스캔 권한을 가진 코드에만 사용할 것.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field

from harness import _call_llm  # 백엔드(cli/api) 재사용

import os

TRIAGE_MODEL = os.environ.get("TRIAGE_MODEL", "sonnet")
TRIAGE_BATCH = int(os.environ.get("SAST_BATCH", "8"))  # 한 LLM 콜에 묶을 finding 수


# ---------------------------------------------------------------------------
# 정규화된 finding
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    tool: str
    rule_id: str
    file: str
    line: int
    severity: str          # 스캐너가 준 원본 심각도
    message: str
    snippet: str = ""
    # 아래는 LLM 트리아지 후 채워짐
    is_true_positive: bool | None = None
    business_severity: str = ""
    reason: str = ""
    fix: str = ""


# ---------------------------------------------------------------------------
# 1. 탐지 — 스캐너 실행(설치된 것만) 후 native JSON 파싱
# ---------------------------------------------------------------------------

def run_semgrep(target: str) -> list[Finding]:
    if not shutil.which("semgrep"):
        print("  [skip] semgrep 미설치 (pip install semgrep)")
        return []
    out = subprocess.run(
        ["semgrep", "scan", "--config", "auto", "--json", "--quiet", target],
        capture_output=True, text=True,
    )
    data = json.loads(out.stdout or "{}")
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        findings.append(Finding(
            tool="semgrep",
            rule_id=r.get("check_id", ""),
            file=r.get("path", ""),
            line=r.get("start", {}).get("line", 0),
            severity=extra.get("severity", "INFO"),
            message=extra.get("message", "").strip(),
        ))
    return findings


def run_trivy(target: str) -> list[Finding]:
    if not shutil.which("trivy"):
        print("  [skip] trivy 미설치")
        return []
    out = subprocess.run(
        ["trivy", "fs", "--format", "json", "--quiet", target],
        capture_output=True, text=True,
    )
    data = json.loads(out.stdout or "{}")
    findings = []
    for res in data.get("Results", []) or []:
        loc = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            findings.append(Finding(
                tool="trivy-sca", rule_id=v.get("VulnerabilityID", ""), file=loc, line=0,
                severity=v.get("Severity", "UNKNOWN"),
                message=f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('Title', '')}",
            ))
        for s in res.get("Secrets", []) or []:
            findings.append(Finding(
                tool="trivy-secret", rule_id=s.get("RuleID", ""), file=loc,
                line=s.get("StartLine", 0), severity=s.get("Severity", "HIGH"),
                message=s.get("Title", ""),
            ))
        for m in res.get("Misconfigurations", []) or []:
            findings.append(Finding(
                tool="trivy-misconf", rule_id=m.get("ID", ""), file=loc, line=0,
                severity=m.get("Severity", "UNKNOWN"), message=m.get("Title", ""),
            ))
    return findings


def run_gitleaks(target: str) -> list[Finding]:
    if not shutil.which("gitleaks"):
        print("  [skip] gitleaks 미설치")
        return []
    with tempfile.NamedTemporaryFile("r", suffix=".json", delete=False) as tf:
        report = tf.name
    # --no-git: 일반 디렉토리도 스캔. gitleaks는 leak 발견 시 exit 1 (정상)
    subprocess.run(
        ["gitleaks", "detect", "--no-git", "--source", target,
         "--report-format", "json", "--report-path", report, "--no-banner"],
        capture_output=True, text=True,
    )
    try:
        data = json.loads(pathlib.Path(report).read_text() or "[]")
    except (json.JSONDecodeError, FileNotFoundError):
        data = []
    findings = []
    for g in data:
        findings.append(Finding(
            tool="gitleaks", rule_id=g.get("RuleID", ""), file=g.get("File", ""),
            line=g.get("StartLine", 0), severity="HIGH",
            message=g.get("Description", "hardcoded secret"),
        ))
    return findings


# ---------------------------------------------------------------------------
# 2. 코드 스니펫 첨부 + dedup
# ---------------------------------------------------------------------------

def attach_snippets(findings: list[Finding], root: str, ctx: int = 3) -> None:
    for f in findings:
        if not f.line:
            continue
        path = pathlib.Path(root) / f.file if not pathlib.Path(f.file).is_absolute() else pathlib.Path(f.file)
        try:
            lines = path.read_text(errors="replace").splitlines()
        except (FileNotFoundError, IsADirectoryError, OSError):
            continue
        lo, hi = max(0, f.line - ctx - 1), min(len(lines), f.line + ctx)
        f.snippet = "\n".join(f"{i+1}: {lines[i]}" for i in range(lo, hi))


def dedup(findings: list[Finding]) -> list[Finding]:
    seen, unique = set(), []
    for f in findings:
        key = (f.file, f.line, f.rule_id)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


# ---------------------------------------------------------------------------
# 3. LLM 트리아지 — 오탐 판별 / 심각도 재랭킹 / 패치 제안 (배치)
# ---------------------------------------------------------------------------

TRIAGE_SYSTEM = """\
너는 SAST 스캐너 결과를 트리아지하는 시니어 앱보안 엔지니어다.
각 finding에 대해 코드 스니펫과 맥락을 보고 판단한다:

- is_true_positive: 실제 익스플로잇 가능한 취약인가(스캐너 오탐이면 false)
- business_severity: 노출면·데이터 민감도를 반영해 재산정 (critical|high|medium|low)
- reason: 판단 근거 한 줄
- fix: 구체적 수정 방향 한 줄

이 서비스는 핀테크다. 금융/개인정보/인증 경로에 닿는 취약은 심각도를 상향한다.
로직 취약점(IDOR 등)은 문법상 멀쩡해도 true positive일 수 있음을 유의한다.

반드시 아래 JSON만 출력한다(설명·백틱 금지):
{ "results": [ { "index": 0, "is_true_positive": true, "business_severity": "high",
                 "reason": "...", "fix": "..." }, ... ] }"""


def triage(findings: list[Finding]) -> None:
    for start in range(0, len(findings), TRIAGE_BATCH):
        batch = findings[start : start + TRIAGE_BATCH]
        items = [
            {
                "index": i,
                "tool": f.tool,
                "rule": f.rule_id,
                "severity": f.severity,
                "message": f.message,
                "file": f.file,
                "line": f.line,
                "snippet": f.snippet,
            }
            for i, f in enumerate(batch)
        ]
        user = "다음 finding들을 트리아지하라:\n" + json.dumps(items, ensure_ascii=False, indent=2)
        raw = _call_llm(TRIAGE_MODEL, TRIAGE_SYSTEM, user, max_tokens=2000)
        try:
            parsed = _parse_json(raw)["results"]
        except (json.JSONDecodeError, KeyError, ValueError):
            print("  [warn] 트리아지 파싱 실패, 이 배치는 원본 심각도 유지")
            continue
        for r in parsed:
            f = batch[r["index"]]
            f.is_true_positive = r.get("is_true_positive")
            f.business_severity = r.get("business_severity", f.severity)
            f.reason = r.get("reason", "")
            f.fix = r.get("fix", "")


def _parse_json(raw: str) -> dict:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("```")[1].lstrip("json").strip()
    start, end = raw.find("{"), raw.rfind("}")
    return json.loads(raw[start : end + 1])


# ---------------------------------------------------------------------------
# 4. 리포트
# ---------------------------------------------------------------------------

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "": 4}


def write_reports(findings: list[Finding], json_path: str) -> None:
    # true positive만, 비즈니스 심각도순 정렬
    tps = [f for f in findings if f.is_true_positive is not False]
    tps.sort(key=lambda f: _SEV_ORDER.get(f.business_severity.lower(), 4))

    pathlib.Path(json_path).write_text(
        json.dumps([asdict(f) for f in tps], ensure_ascii=False, indent=2)
    )

    md = ["# SAST 트리아지 리포트", ""]
    fp_count = sum(1 for f in findings if f.is_true_positive is False)
    md.append(f"- 원본 finding: {len(findings)}건 / 오탐 제거: {fp_count}건 / 유효: {len(tps)}건\n")
    for f in tps:
        md.append(f"## [{f.business_severity.upper() or f.severity}] {f.rule_id} ({f.tool})")
        md.append(f"- 위치: `{f.file}:{f.line}`")
        md.append(f"- 근거: {f.reason or f.message}")
        if f.fix:
            md.append(f"- 수정: {f.fix}")
        md.append("")
    md_path = json_path.rsplit(".", 1)[0] + ".md"
    pathlib.Path(md_path).write_text("\n".join(md))
    print(f"\n리포트: {json_path} , {md_path}")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=".", help="스캔할 코드 경로")
    ap.add_argument("--report", default="sast-report.json")
    ap.add_argument("--agent", action="store_true",
                    help="에이전트 로직 감사 패스 추가(스캐너가 못 잡는 로직/설계 결함)")
    args = ap.parse_args()

    print(f"[1/3] 스캐너 실행 (target={args.target})")
    findings = run_semgrep(args.target) + run_trivy(args.target) + run_gitleaks(args.target)
    findings = dedup(findings)
    attach_snippets(findings, args.target)
    if findings:
        print(f"[2/3] {len(findings)}건 정규화·dedup 완료. LLM 트리아지 중...")
        triage(findings)
    else:
        print("[2/3] 스캐너 finding 없음 (미설치이거나 클린).")

    # 선택: 에이전트 로직 감사 패스를 한 층 더 얹는다(탐지=LLM 추론)
    if args.agent:
        print("[+] 에이전트 로직 감사 패스")
        from agent_audit import run_agent_audit  # 지연 import(순환 방지)
        findings += run_agent_audit(args.target)

    if not findings:
        pathlib.Path(args.report).write_text("[]")
        return 0

    print("[3/3] 리포트 생성")
    write_reports(findings, args.report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
