# Phase 1 — Semgrep (SAST: 코드 정적분석)

## 1. Semgrep이 언제 필요한가

**내가 직접 짠 코드**에 위험한 패턴이 들어갔는지 본다. 코드를 실행하지 않고
(=정적, static) 소스만 읽어서 "이런 모양이면 위험" 규칙에 맞춰 훑는다.

이런 걸 잡는다:
- 커맨드 인젝션 (`subprocess(..., shell=True)` + 사용자 입력)
- 코드 인젝션 (`eval(입력)`)
- SQL 인젝션 (문자열로 SQL 조립)
- 경로 순회 (사용자 입력으로 파일 경로 조합)
- 위험한 설정 (`debug=True`, `host=0.0.0.0`)

**언제 돌리나:** 커밋/PR마다. 코드가 바뀔 때마다 새로 짠 코드에 구멍이 없는지 확인.

**Trivy/Gitleaks와 차이:** Semgrep은 "코드 로직이 위험하게 짜였나"를 본다.
가져다 쓴 라이브러리 CVE(→Trivy)나 하드코딩된 비밀(→Gitleaks)이 아니라,
**내가 쓴 코드 자체의 패턴**이 대상이다.

---

## 2. 기본 스캔 — 직접 따라 하기

### 2-1. 자동 규칙으로 스캔
```bash
semgrep --config auto study/lab
```

`--config auto` = Semgrep이 언어(파이썬)를 감지해서 Registry의 관련 규칙셋을
자동으로 받아 적용. 처음엔 이거면 충분하다.

### 2-2. 실제 결과 (이 랩에서 나온 것)

우리 랩에서 **16개**가 잡혔다:

```
  subprocess-shell-true          app.py:18   ← 커맨드 인젝션
  eval-detected                  app.py:25   ← 코드 인젝션
  formatted-sql-query            app.py:34   ← SQL 인젝션
  path-traversal-open            app.py:41   ← 경로 순회
  debug-enabled                  app.py:47   ← 위험 설정
  detected-stripe-api-key        config.py:14 ← 시크릿(부수적으로 잡힘)
  ...
```

### 2-3. 출력 읽는 법

각 finding은 이렇게 생겼다:
```
❯❱ python.lang.security.audit.formatted-sql-query.formatted-sql-query
      ❰❰ Blocking ❱❱                       ← 심각도/차단 여부
      Detected possible formatted SQL query...  ← 설명
      Details: https://sg.run/EkWw          ← 규칙 문서 링크
       34┆ query = "SELECT * FROM users..."  ← 문제의 코드 줄
```

- **규칙 ID** (`python.lang.security...`): 어떤 규칙이 걸렸는지. 점(.)으로 구분된 경로.
- **Blocking**: 이건 "CI에서 막아야 할 급"이라는 Semgrep의 기본 분류.
- **줄 번호**: 정확히 어느 줄인지.

> 하나의 취약점을 여러 규칙이 동시에 잡기도 한다 (예: SQL 인젝션을 3개 규칙이 각각).
> 그래서 "취약점 개수 ≠ finding 개수"다.

---

## 3. 자주 쓰는 옵션

```bash
# JSON으로 뽑기 (자동화/CI용)
semgrep --config auto study/lab --json -o semgrep.json

# SARIF로 뽑기 (GitHub Security 탭에 올릴 때)
semgrep --config auto study/lab --sarif -o semgrep.sarif

# 특정 규칙셋만 (보안 감사 규칙)
semgrep --config "p/security-audit" study/lab

# 파이썬 전용 규칙셋
semgrep --config "p/python" study/lab

# 발견이 있으면 종료코드 1 (CI에서 실패시키는 핵심)
semgrep --config auto study/lab --error
```

`p/...`는 Semgrep Registry의 **큐레이션된 규칙 묶음(pack)**이다. 유명한 것들:
- `p/security-audit` — 보안 감사 전반
- `p/secrets` — 시크릿 탐지
- `p/owasp-top-ten` — OWASP Top 10
- `p/ci` — CI에 적합한 정제된 셋

---

## 4. 오탐(false positive) 다루기 — `.semgrepignore`와 인라인 무시

실무에선 "이건 의도된 코드다" 하는 경우가 있다. 두 가지 방법:

### 4-1. 특정 줄만 무시
```python
return subprocess.call(cmd, shell=True)  # nosemgrep
# 또는 특정 규칙만:
return subprocess.call(cmd, shell=True)  # nosemgrep: python.lang.security...
```

### 4-2. 파일/폴더 통째로 무시 — `.semgrepignore`
```
# study/.semgrepignore
tests/
*.md
```

> ⚠️ 무시는 신중히. "이해했고 안전하다"가 아니라 "귀찮아서" 무시하면 사고 난다.

---

## 5. 나만의 규칙 만들기 (맛보기)

Semgrep의 진짜 힘은 **커스텀 규칙**이다. YAML로 "이런 패턴 찾아줘"를 직접 쓴다.

`study/lab/rules/no-eval.yml`:
```yaml
rules:
  - id: no-eval-on-request
    languages: [python]
    severity: ERROR
    message: "eval() 사용 금지. 사용자 입력이면 RCE로 이어진다."
    pattern: eval(...)
```

적용:
```bash
semgrep --config study/lab/rules/no-eval.yml study/lab
```

`pattern: eval(...)` 에서 `...`는 "인자 아무거나"를 뜻하는 Semgrep 메타변수.
문법 트리(AST) 기준으로 매칭하기 때문에 공백/줄바꿈에 안 흔들린다.

---

## 6. CI 연동 (미리보기 — 자세한 건 Phase 4)

핵심은 **"발견되면 종료코드 1 → 파이프라인 실패"**로 게이트를 만드는 것.

```yaml
# GitHub Actions 예시 (일부)
- name: Semgrep
  run: semgrep --config auto . --error --sarif -o semgrep.sarif
```

처음 도입할 땐 `--error`를 빼고 **리포트만**(non-blocking) 하다가,
기존 코드 정리가 끝나면 게이트로 전환하는 게 현실적이다. (Phase 4에서 다룸)

---

## ✅ Phase 1 체크리스트

- [ ] `semgrep --config auto study/lab` 실행해서 16개 finding 확인
- [ ] finding 하나 골라서 규칙 ID·줄번호·설명 읽어보기
- [ ] `--json`, `--sarif`로 출력 형식 바꿔보기
- [ ] `# nosemgrep`으로 한 줄 무시해보기
- [ ] 커스텀 규칙 `no-eval.yml` 만들어 적용해보기

끝냈으면 `study/README.md`의 Phase 1 체크박스를 `[x]`로, 학습 로그에 한 줄 기록.
→ 다음: [`02-trivy.md`](02-trivy.md)
