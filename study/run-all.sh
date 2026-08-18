#!/usr/bin/env bash
# 로컬 리허설: 세 스캐너를 CI에서 돌 때와 똑같이 돌려본다.
# CI에 넣기 전에 로컬에서 결과/종료코드를 먼저 확인하는 용도.
#
# 사용법:
#   bash study/run-all.sh            # 리포트만 (실패해도 계속)
#   bash study/run-all.sh --gate     # 게이트 모드 (발견되면 실패로 종료)
set -u

TARGET="study/lab"
GATE="${1:-}"
FAIL=0

section() { printf '\n\033[1;36m========== %s ==========\033[0m\n' "$1"; }

section "1) Semgrep — 코드 정적분석 (SAST)"
semgrep --config auto "$TARGET" ${GATE:+--error}
[ $? -ne 0 ] && FAIL=1

section "2) Trivy — 의존성/설정/시크릿 (SCA)"
trivy fs "$TARGET" --severity HIGH,CRITICAL ${GATE:+--exit-code 1}
[ $? -ne 0 ] && FAIL=1

section "3) Gitleaks — 시크릿 스캔"
gitleaks detect --source "$TARGET" --no-git --redact -v ${GATE:+--exit-code 1}
[ $? -ne 0 ] && FAIL=1

section "요약"
if [ "$GATE" = "--gate" ] && [ $FAIL -ne 0 ]; then
  echo "❌ 게이트 실패 — 발견된 문제가 있습니다. (CI라면 여기서 배포 차단)"
  exit 1
else
  echo "✅ 완료. (게이트 모드로 보려면: bash study/run-all.sh --gate)"
fi
