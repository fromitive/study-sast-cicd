# SAST CI/CD 실습 (Semgrep · Trivy · Gitleaks)

이 폴더는 **손으로 따라 하며 배우는 실습 랩**이다. 세 개의 보안 스캐너를
0에서부터 하나씩 익히고, 마지막에 CI/CD 파이프라인 하나로 합친다.

> 이 파일이 **학습 컨텍스트(진행 상황) 파일**이다. 세션이 바뀌어도 이 파일을 열면
> 어디까지 했는지, 다음에 뭘 할지 이어서 할 수 있다.

---

## 큰 그림 — 세 도구는 각각 '다른 종류의 위험'을 본다

파이프라인에 셋을 다 넣는 이유는 **서로 겹치지 않는 영역**을 커버하기 때문이다.

| 도구 | 분류 | 무엇을 보나 | 예시 |
|---|---|---|---|
| **Semgrep** | SAST (코드 정적분석) | **내가 쓴 코드**의 취약 패턴 | `eval(입력)`, SQL 인젝션, 커맨드 인젝션 |
| **Trivy** | SCA + 이미지/IaC | **가져다 쓴 것**의 알려진 취약점(CVE) | 오래된 라이브러리, 취약 도커 이미지, 잘못된 설정 |
| **Gitleaks** | 시크릿 스캔 | **실수로 커밋한 비밀** | AWS 키, DB 비밀번호, API 토큰 |

한 문장 요약:
- **Semgrep** = "내 코드가 위험하게 짜였나?"
- **Trivy** = "내가 의존하는 것들이 이미 알려진 구멍이 있나?"
- **Gitleaks** = "비밀을 코드에 박아놨나?"

셋 다 **결정론적(매번 같은 결과) · 빠름 · 무료**. 그래서 CI에 넣기 딱 좋다.

---

## 학습 로드맵 (단계별)

각 단계는 `guides/` 안에 별도 문서가 있다. **순서대로** 진행.

- [ ] **Phase 0 — 준비** (설치·랩 이해) → 아래 "준비" 섹션
- [ ] **Phase 1 — Semgrep** → [`guides/01-semgrep.md`](guides/01-semgrep.md)
- [ ] **Phase 2 — Trivy** → [`guides/02-trivy.md`](guides/02-trivy.md)
- [ ] **Phase 3 — Gitleaks** → [`guides/03-gitleaks.md`](guides/03-gitleaks.md)
- [ ] **Phase 4 — CI/CD 통합** → [`guides/04-cicd.md`](guides/04-cicd.md)

> 한 단계 끝낼 때마다 위 체크박스를 `[x]`로 바꾸고, 배운 점을 아래 "학습 로그"에 한 줄 적자.

---

## 준비 (Phase 0)

### 설치 상태
이 랩에서는 아래 버전으로 진행했다 (macOS + Homebrew 기준):

```bash
brew install semgrep trivy gitleaks
```

- semgrep 1.173.0
- trivy 0.74.0
- gitleaks 8.30.1

확인:
```bash
semgrep --version && trivy --version && gitleaks version
```

### 실습 대상 — `lab/` (일부러 취약하게 만든 앱)

| 파일 | 심어둔 취약점 | 주로 잡는 도구 |
|---|---|---|
| `lab/app.py` | 커맨드 인젝션·eval·SQL 인젝션·경로순회·debug 모드 | **Semgrep** |
| `lab/requirements.txt` | 오래된 취약 버전 라이브러리(CVE) | **Trivy** |
| `lab/Dockerfile` | 오래된 베이스 이미지·root 실행·이미지에 박힌 시크릿 | **Trivy** |
| `lab/config.py` | 하드코딩된 AWS 키·DB 비번·API 토큰 | **Gitleaks** |

> ⚠️ `lab/`은 교육용이다. 실제 서비스 코드로 복붙하지 말 것.

---

## 학습 로그 (여기에 진행하며 기록)

- 2026-08-18 · Phase 0 완료 · semgrep/trivy/gitleaks 설치, 랩 구조 구축. 3종 스캔 정상 동작 확인(semgrep 16 / trivy 29 CVE / gitleaks 2).
-

---

## 자주 쓰는 명령어 치트시트

```bash
# Semgrep — 코드 스캔
semgrep --config auto study/lab

# Trivy — 의존성/파일시스템 스캔
trivy fs study/lab

# Gitleaks — 시크릿 스캔 (작업 트리)
gitleaks detect --source . --no-git
```

전체 파이프라인 한 방에 돌려보기(로컬 리허설):
```bash
bash study/run-all.sh
```
