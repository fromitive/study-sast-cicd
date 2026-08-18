"""
회귀 게이트
===========

한 번 등록된 결함(findings.jsonl)을 배포마다 재실행한다.
- 이제 잘 방어하면(defended) → 통과
- 다시 뚫리면(broken) → 회귀! → 종료코드 1 로 CI 파이프라인을 fail 시킨다.

이게 "재발 방지"의 실체다. LDAP에서 놓친 유형을 리뷰 체크포인트로 등록했던 것과
정확히 같은 구조 — 뚫린 케이스를 자동 재검증 대상으로 못박는다.
"""

from __future__ import annotations

import json
import pathlib
import sys

from harness import FINDINGS_PATH, Judge, MockTarget, Objective, Target, _run_turns, load_objectives


def _objectives_by_id() -> dict[str, Objective]:
    return {o.id: o for o in load_objectives()}


def run_regression(target: Target) -> int:
    if not FINDINGS_PATH.exists():
        print("등록된 회귀 케이스 없음. 통과.")
        return 0

    judge = Judge()
    objs = _objectives_by_id()
    regressions = []

    for line in FINDINGS_PATH.read_text(encoding="utf-8").splitlines():
        case = json.loads(line)
        obj = objs[case["objective_id"]]
        responses = _run_turns(target, case["turns"])
        score = judge.score(obj, case["turns"], responses)

        status = "OK(방어됨)" if score["verdict"] == "defended" else "REGRESSION"
        print(f"[{status}] {case['objective_id']} — {score['reason']}")

        if score["verdict"] != "defended":
            regressions.append(case["objective_id"])

    if regressions:
        print(f"\n❌ 회귀 {len(regressions)}건: {regressions} — 배포 차단")
        return 1

    print("\n✅ 모든 과거 결함이 여전히 방어됨 — 통과")
    return 0


if __name__ == "__main__":
    # 실제: target = HTTPTarget("https://our-chatbot/api/chat", headers={...})
    sys.exit(run_regression(MockTarget()))
