# Phase 4 — CI/CD 통합 (세 도구를 파이프라인 하나로)

앞의 세 스캐너를 CI에 붙여, **코드가 올라올 때마다 자동으로** 돌게 만든다.

## 1. 먼저 로컬에서 리허설

CI에 넣기 전에, CI에서 돌 명령을 로컬에서 똑같이 돌려본다:
```bash
bash study/run-all.sh          # 리포트만
bash study/run-all.sh --gate   # 게이트 모드 (발견되면 종료코드 1)
```
`--gate`가 붙으면 각 도구에 `--error`/`--exit-code 1`이 붙어서, 실제 CI가
배포를 막는 것과 같은 동작을 한다. 로컬에서 종료코드부터 확인하는 습관이 중요.

## 2. CI 설정 파일

바로 쓸 수 있는 설정을 만들어뒀다:
- **GitHub Actions** → [`../ci/github-actions.yml`](../ci/github-actions.yml)
  → 레포의 `.github/workflows/security.yml`로 복사
- **GitLab CI** → [`../ci/gitlab-ci.yml`](../ci/gitlab-ci.yml)
  → 레포 루트 `.gitlab-ci.yml`에 병합

## 3. ★도입 전략 — "처음부터 다 막으면 실패한다"

가장 흔한 실수: 기존 코드에 스캐너를 켜자마자 **게이트(blocking)로** 걸어버리는 것.
그러면 첫날부터 파이프라인이 빨갛고, 팀은 "그냥 꺼"라고 한다. 스캐너 도입은
**기술이 아니라 운영 전략** 문제다.

권장 순서:
| 단계 | Semgrep | Trivy | Gitleaks |
|---|---|---|---|
| 1. 도입 초기 | 리포트만 | 리포트만 | **게이트** |
| 2. 정리 중 | 리포트만 | 게이트(HIGH+) | 게이트 |
| 3. 안정화 | 게이트 | 게이트 | 게이트 |

- **Gitleaks만 처음부터 게이트**로 두는 이유: 시크릿은 한 번 새면 되돌릴 수 없다.
  기존 코드 정리와 무관하게, **새로 들어오는 비밀은 무조건 막는 게** 이득이다.
- Semgrep/Trivy는 기존 코드에 발견이 많으니, 먼저 **베이스라인**을 잡고
  "**새로 늘어난 것만**" 막는 식으로 간다.

## 4. 리포트만 vs 게이트 — 기술적으로 뭐가 다른가

**종료코드(exit code)** 하나가 전부다.
- 리포트만: 발견돼도 종료코드 0 → 파이프라인 초록 → 배포 진행
- 게이트: 발견되면 종료코드 1 → 파이프라인 빨강 → 배포 차단

| 도구 | 게이트로 만드는 옵션 |
|---|---|
| Semgrep | `--error` |
| Trivy | `--exit-code 1` (+ `--severity HIGH,CRITICAL`) |
| Gitleaks | `--exit-code 1` (기본이 1) |

## 5. SARIF — 결과를 한곳에 모으기

세 도구 다 **SARIF** 포맷으로 뽑을 수 있다. GitHub라면 SARIF를 업로드하면
**Security 탭**에 취약점이 코드 위치와 함께 모여 보인다(중복 추적/해결 상태 관리).
```bash
semgrep ... --sarif -o semgrep.sarif
trivy   ... -f sarif -o trivy.sarif
gitleaks ... -f sarif -o gitleaks.sarif
```
CI 설정 파일들이 이미 SARIF 업로드까지 포함하고 있다.

## 6. 정기 스캔도 걸어라

Trivy의 CVE는 **어제 안전했어도 오늘 새 취약점이 뜬다**(코드가 안 바뀌어도).
그래서 push/PR 트리거뿐 아니라 `schedule`(매일 cron)도 걸어둔다.
→ `github-actions.yml`의 `schedule: cron` 참고.

## 7. 이 레포의 기존 파이프라인과의 관계

루트의 `.gitlab-ci.yml`엔 이미 **AI 레드팀 + SAST 트리아지** 파이프라인이 있다
(상위 프로젝트). 우리가 만든 `study/ci/*`는 **스캐너 3종만 떼어낸 학습용 최소 버전**이다.
개념을 익힌 뒤, 상위 프로젝트의 `sast.py`(스캐너+LLM 트리아지)가 이 세 도구를
어떻게 감싸는지 비교해보면 이해가 깊어진다.

## ✅ Phase 4 체크리스트

- [ ] `bash study/run-all.sh` 와 `--gate` 둘 다 돌려서 종료코드 차이 확인
- [ ] `study/ci/github-actions.yml`(또는 gitlab)을 실제 레포에 붙여 파이프라인 초록/빨강 확인
- [ ] Gitleaks만 게이트, 나머지 리포트로 시작해보기
- [ ] Semgrep/Trivy를 게이트로 승격(`--error`/`--exit-code 1`)해보기
- [ ] `schedule` 정기 스캔이 도는지 확인

전 과정을 마치면 `study/README.md`의 모든 체크박스를 채우고, 학습 로그를 정리하자. 🎉
