# Phase 2 — Trivy (SCA + 이미지/설정 스캔)

## 1. Trivy가 언제 필요한가

Semgrep이 "**내가 쓴 코드**"를 봤다면, Trivy는 "**내가 가져다 쓴 것**"을 본다.

- **SCA (의존성 스캔):** `requirements.txt`, `package.json`, `go.mod` 등에 적힌
  라이브러리들이 **알려진 취약점(CVE)** 이 있는 버전인지. → 이게 핵심.
- **컨테이너 이미지 스캔:** 도커 이미지 안 OS 패키지·라이브러리의 CVE.
- **IaC/설정 오류(misconfig):** Dockerfile, Kubernetes, Terraform의 나쁜 설정.
- **시크릿:** 부수적으로 하드코딩된 비밀도 잡는다 (Gitleaks와 겹침).

**언제 돌리나:** 의존성이 바뀔 때(=lockfile 변경), 이미지 빌드할 때, 그리고
**정기적으로**(어제는 안전했던 버전이 오늘 새 CVE가 뜰 수 있으니까).

> 핵심 차이: Semgrep의 대상은 "패턴", Trivy의 대상은 "알려진 CVE 목록"이다.
> Trivy는 취약점 DB를 내려받아 대조한다. 그래서 **DB 최신화가 중요**하다.

---

## 2. 기본 스캔 — 직접 따라 하기

### 2-1. 파일시스템 스캔 (의존성 + 시크릿 + 설정 한 번에)
```bash
trivy fs study/lab
```

기본으로 `vuln`(CVE), `secret`(시크릿), `misconfig`(설정오류)를 다 본다.
스캐너를 골라 켤 수도 있다:
```bash
trivy fs study/lab --scanners vuln          # CVE만
trivy fs study/lab --scanners vuln,secret,misconfig
```

> 첫 실행 시 취약점 DB(수백 MB)를 내려받는다. 이후엔 캐시라 빠르다.

### 2-2. 실제 결과 (이 랩에서 나온 것)

**의존성(requirements.txt)에서 CVE 29개:**
```
Total: 29 (LOW: 1, MEDIUM: 15, HIGH: 11, CRITICAL: 2)

flask   CVE-2018-1000656  HIGH   설치:0.12.2  →  수정:0.12.3   (DoS)
jinja2  CVE-2019-10906    HIGH   설치:2.10    →  수정:2.10.1   (샌드박스 탈출)
...
```
읽는 법:
- **Installed Version** = 지금 내 버전, **Fixed Version** = 올려야 할 버전.
- 대응은 보통 "**Fixed Version 이상으로 업그레이드**". 그게 조치의 90%다.
- `Status: fixed` = 패치가 나와 있음(=올리면 됨). `affected`/`will_not_fix`도 있다.

**Dockerfile 설정 오류(misconfig):**
```
DS-0031 (CRITICAL): ENV에 시크릿 노출  → 이미지에 AWS 키가 박힘
DS-0002 (HIGH):     마지막 USER가 root → 컨테이너가 root로 실행
DS-0026 (LOW):      HEALTHCHECK 없음
```

**config.py 시크릿:** Stripe(CRITICAL), Slack(MEDIUM) — Gitleaks와 겹쳐 잡힘.

---

## 3. 심각도 필터 · CI 게이트 만들기

```bash
# HIGH 이상만 보기
trivy fs study/lab --severity HIGH,CRITICAL

# 패치 가능한 것만 (당장 조치할 수 있는 것에 집중)
trivy fs study/lab --ignore-unfixed

# HIGH/CRITICAL이 있으면 종료코드 1 → CI 실패 (게이트의 핵심)
trivy fs study/lab --severity HIGH,CRITICAL --exit-code 1
```

`--exit-code 1` 이 게이트의 열쇠다. 기본값은 0(발견돼도 성공)이라,
CI에서 막고 싶으면 명시적으로 켜야 한다.

---

## 4. 컨테이너 이미지 스캔 (도커 있을 때)

> 이 랩 머신엔 docker가 없어도 위 `trivy fs`는 다 된다. 이미지 스캔만 도커 필요.

```bash
# 빌드한 이미지 스캔
docker build -t mylab study/lab
trivy image mylab

# 원격 이미지도 바로 (빌드 없이)
trivy image python:3.9-slim --severity HIGH,CRITICAL
```

이미지 스캔은 OS 패키지(apt/apk)와 언어 라이브러리 CVE를 함께 본다.
"오래된 베이스 이미지"가 CVE 폭탄인 경우가 많다 → **slim/distroless 최신 태그** 권장.

---

## 5. 출력 형식 (CI/리포트용)

```bash
trivy fs study/lab -f json   -o trivy.json
trivy fs study/lab -f sarif  -o trivy.sarif    # GitHub Security 탭
trivy fs study/lab -f table                     # 사람이 읽기 (기본)
```

---

## 6. 오탐/수용 다루기 — `.trivyignore`

"이 CVE는 지금 못 고친다 / 우리한테 해당 안 된다"를 기록:
```
# study/.trivyignore
CVE-2018-1000656
CVE-2019-1010083 exp:2026-12-31   # 만료일 지정 가능
```

> 무시할 땐 **이유와 만료일**을 같이. "왜 무시했는지" 남기는 게 감사의 핵심.

---

## 7. CI 연동 (미리보기 — Phase 4)

```yaml
# GitHub Actions 예시 (일부)
- name: Trivy
  run: trivy fs . --severity HIGH,CRITICAL --exit-code 1 -f sarif -o trivy.sarif
```

의존성 스캔은 **매일 정기 실행**도 걸어두면 좋다(새 CVE 대응). Phase 4 참고.

---

## ✅ Phase 2 체크리스트

- [ ] `trivy fs study/lab` 실행 → CVE 29개 + 미스컨픽 + 시크릿 확인
- [ ] `--severity HIGH,CRITICAL`로 필터해보기
- [ ] `requirements.txt`의 flask 버전을 최신으로 올리고 다시 스캔 → CVE 줄어드는 것 확인
- [ ] `--exit-code 1` 붙여 종료코드 확인 (`echo $?`)
- [ ] (도커 있으면) `trivy image python:3.9-slim` 돌려보기

끝냈으면 `study/README.md` 체크박스·로그 갱신 → 다음: [`03-gitleaks.md`](03-gitleaks.md)
