# Phase 3 — Gitleaks (시크릿 스캔)

## 1. Gitleaks가 언제 필요한가

**비밀(secret)이 코드/커밋 히스토리에 들어갔는지**만 집중해서 본다.
AWS 키, DB 비밀번호, API 토큰, 프라이빗 키 등.

Semgrep/Trivy도 시크릿을 조금 잡지만, Gitleaks는 **git 히스토리 전체**를
훑을 수 있는 게 강점이다. 지금 코드엔 없어도 **과거 커밋에 한 번 올렸다면
이미 유출**이다 (git은 다 기억한다). 그걸 찾아낸다.

**언제 돌리나:**
- 커밋/PR마다 (새로 들어오는 비밀 차단)
- **pre-commit 훅**으로 커밋 전에 (가장 효과적 — 아예 못 들어가게)
- 레포 도입 초기에 히스토리 전체 1회 스캔 (이미 새어나간 것 찾기)

---

## 2. 기본 스캔 — 직접 따라 하기

Gitleaks는 두 가지 모드가 있다. 차이를 이해하는 게 중요하다.

### 2-1. `--no-git`: 현재 파일 내용만 (git 히스토리 무시)
```bash
gitleaks detect --source study/lab --no-git -v
```
지금 디스크에 있는 파일들만 본다. 커밋 안 한 파일도 잡는다.

### 2-2. git 히스토리 스캔 (기본 모드)
```bash
gitleaks detect --source . -v
```
`.git`의 **모든 커밋**을 훑는다. "과거에 올렸다 지운 비밀"까지 찾는다.
→ 레포 처음 받았을 때 이걸 한 번 돌리는 게 핵심.

### 2-3. 실제 결과 (이 랩)
```
RuleID:  stripe-access-token   File: config.py:14
RuleID:  slack-webhook-url      File: config.py:17
→ leaks found: 2, 종료코드 1
```

---

## 3. ★중요한 교훈 — "왜 AWS 키는 안 잡혔나?"

`config.py`엔 AWS 키(`AKIAIOSFODNN7EXAMPLE`)도 있는데 Gitleaks는 **안 잡았다.**
버그가 아니다. 이건 **AWS 공식 문서의 예제 키**라서, Gitleaks 기본 규칙의
**allowlist(허용목록)** 에 "이런 유명한 더미 키는 무시"로 등록돼 있다.

교훈 두 가지:
1. **스캐너는 오탐을 줄이려 allowlist를 갖는다.** 유명한 예제/테스트 값은 일부러 무시.
2. **그래서 학습·테스트할 땐 '진짜같지만 가짜'인 값**을 써야 도구가 반응한다.
   (우리 Stripe/Slack 값은 형태가 진짜 같아서 잡혔다.)

실무 함의: allowlist를 과신하면 진짜 비밀을 놓칠 수 있다. 반대로 너무 좁히면
오탐 폭탄. **규칙/allowlist를 이해하고 튜닝**하는 게 시크릿 스캔의 실력이다.

---

## 4. 결과 리포트로 뽑기

```bash
gitleaks detect --source . -f json   -o gitleaks.json
gitleaks detect --source . -f sarif  -o gitleaks.sarif   # GitHub Security 탭
```

종료코드: **비밀 발견 시 1** (기본). CI 게이트에 그대로 쓸 수 있다.
발견돼도 실패시키기 싫으면 `--exit-code 0`.

---

## 5. pre-commit 훅 — 커밋 전에 막기 (가장 강력)

비밀은 **한 번 커밋되면 히스토리에 영원히 남는다.** 그래서 최선은
**아예 커밋 안 되게** 하는 것. `protect` 모드가 스테이징된 변경만 검사한다.

간단한 훅 (`.git/hooks/pre-commit`):
```bash
#!/bin/sh
gitleaks protect --staged --no-banner || {
  echo "❌ 시크릿 감지! 커밋 취소. 비밀을 제거하고 다시 커밋하세요."
  exit 1
}
```
```bash
chmod +x .git/hooks/pre-commit
```

또는 `pre-commit` 프레임워크(`.pre-commit-config.yaml`)로 팀 전체 공유.

---

## 6. 오탐/수용 다루기 — `.gitleaks.toml`

커스텀 규칙·allowlist를 직접 정의:
```toml
# .gitleaks.toml
title = "our config"
[extend]
useDefault = true          # 기본 규칙 위에 얹기

[[rules]]
id = "internal-token"
regex = '''INT_[A-Z0-9]{32}'''
description = "사내 토큰 형식"

[allowlist]
paths = ['''study/lab/.*''']       # 실습 랩은 통째로 허용(일부러 심은 것)
regexes = ['''EXAMPLE''']          # EXAMPLE 들어간 더미는 무시
```
적용: `gitleaks detect --config .gitleaks.toml --source .`

---

## 7. ★비밀이 이미 유출됐다면 (중요한 실무 상식)

코드에서 **지우는 것만으론 부족하다.** git 히스토리엔 남아 있고,
이미 push 됐다면 누군가 봤을 수 있다. 순서는:
1. **먼저 그 비밀을 무효화(rotate)** — 키 폐기/재발급. 이게 1순위.
2. 그다음 코드/히스토리에서 제거 (`git filter-repo` 등).

> "지웠으니 됐다"가 아니라 "**폐기했으니 됐다**"가 정답.

---

## 8. CI 연동 (미리보기 — Phase 4)

```yaml
# GitHub Actions 예시 (일부)
- name: Gitleaks
  run: gitleaks detect --source . --redact -v --exit-code 1
```
`--redact`는 로그에 비밀 원문이 찍히지 않게 가린다(CI 로그도 유출 경로!).

---

## ✅ Phase 3 체크리스트

- [ ] `gitleaks detect --source study/lab --no-git -v` → 2개(Stripe, Slack) 확인
- [ ] AWS 키가 왜 안 잡혔는지 이해 (allowlist / 예제 키)
- [ ] `gitleaks detect --source .` (히스토리 모드) 돌려보기
- [ ] `--redact` 붙여서 비밀이 가려지는지 확인
- [ ] pre-commit 훅 만들어서 시크릿 넣고 커밋 시도 → 막히는지 확인

끝냈으면 `study/README.md` 갱신 → 다음: [`04-cicd.md`](04-cicd.md)
