# Policy Analyzer — 작업 핸드오프

> **이 파일을 읽는 Claude에게:** 이 문서는 다른 환경의 Claude 세션에서 작업을 이어받기 위한 컨텍스트입니다.
> 먼저 이 파일을 읽고, 필요하면 `DEPLOYMENT_PLAN.md`, `README.md`, `app.py`, `db.py` 를 추가로 읽으세요.

---

## 현재 버전: v3.5

## 프로젝트 요약

Innotium Policy Analyzer — Flask 웹앱으로 이노티움 6개 보안제품의 정책 JSON을 번역/시뮬레이션/진단하는 도구.
Claude AI(claude-sonnet-4-6) + MariaDB(innoplatform) 직접 연동.

## 완료된 작업 (Phase 1 완료)

| 항목 | 상태 | 파일 |
|------|------|------|
| Gemini → Claude API 전환 | ✅ | app.py |
| MariaDB 직접 연동 + Connection Pooling | ✅ | db.py |
| 서버 배포 (Gunicorn + Nginx + systemd) | ✅ | 서버 /app/policy-analyzer/ |
| Frontend DB 조회 UI | ✅ | script.js, index.html |
| Frontend 로그 분석 탭 | ✅ | script.js, index.html |
| 대시보드 UI (빈 화면에 DB 현황) | ✅ | script.js, index.html, style.css |
| 매니저 ↔ Policy Analyzer 상호 링크 | ✅ | patch_main.py (manager+user) |
| Few-Shot 피드백 시스템 | ✅ | db.py, app.py, script.js |
| .env.example | ✅ | .env.example |

## 서버 환경 (2개)

### 집 환경 (2026-03-31 구성 완료)
```
SSH: root@172.30.1.44 (id_rsa 키 인증)
배포 경로: /app/policy-analyzer/
웹 접속: http://172.30.1.44:40010
매니저: http://172.30.1.44:40000
DB: 127.0.0.1:43306 root/Qwert1!2@
서비스: systemctl restart policy-analyzer
Nginx: /etc/nginx/conf.d/policy-analyzer.conf (포트 40010)
로그: /var/log/nginx/, /log/policy-analyzer/
```

### 회사 환경 (v3.0 상태, 업그레이드 필요)
```
SSH: root@192.168.11.97 (비밀번호: Qwert)
배포 경로: /app/policy-analyzer/ (있다면)
웹 접속: http://192.168.11.97:40010
매니저: http://192.168.11.97:40000
DB: 동일 구조 (43306, Qwert1!2@)
```

## 핵심 계정 정보

- **MariaDB**: root / Qwert1!2@, innoplatform / Qwert1!2@ (innoplatform 비밀번호 변경 시 application.yml도 변경 → 기술연구소 문의)
- **웹 관리자**: admin / Qwert1!2@
- **DB명**: innoplatform (실 데이터), innoplatformlog (로그)
- **포트**: 40000(웹), 40001(에이전트), 43306(DB), 46379(Redis)

## 회사에서 v3.0 → v3.5 업그레이드 방법

### 방법 A: git pull (추천)
```bash
# 회사 PC에서
cd /path/to/innotium_policy_translator
git pull origin main   # 또는 해당 브랜치
```

### 방법 B: 수동 scp
```bash
scp -r app.py db.py parser.py patch_main.py .env.example requirements.txt static/ root@192.168.11.97:/app/policy-analyzer/
ssh root@192.168.11.97
cd /app/policy-analyzer && source venv/bin/activate && pip install -r requirements.txt
systemctl restart policy-analyzer
python3 /app/policy-analyzer/patch_main.py
```

### 서버 배포 시 주의사항
1. `.env`에서 IP를 회사 환경에 맞게 수정 (172.30.1.44 → 192.168.11.97)
2. `app.py` CORS origins도 회사 IP로 변경
3. `static/index.html`의 매니저 서버 링크도 회사 IP로 변경
4. `patch_main.py`의 POLICY_ANALYZER_URL도 회사 IP로 변경
5. DB root@127.0.0.1 TCP 권한 필요 (GRANT ALL ON innoplatform.* TO 'root'@'127.0.0.1')

## 아키텍처 참고

매니저 서버 = nginx(40000/40001) → tomcat(Spring Boot WAR) → MariaDB(43306) + Redis(46379)
Policy Analyzer = nginx(40010) → gunicorn(5000) → Flask + Claude API
둘은 MariaDB를 공유함.

설정파일 4개: cms.conf, cmsapi.conf, application.yml, config.js
application.yml 변경 후 WAR 재패키징 필수 (jar -cvf ...)

## 다음 작업 (Phase 2)

| 우선순위 | 항목 |
|---------|------|
| 1 | 통합 정책 조립 (JOIN) — 에이전트에게 내려가는 형태로 조립 |
| 2 | 사용자/부서별 정책 조회 (tb_user_agent_policy JOIN) |
| 3 | 정책 변경 이력 타임라인 |
| 4 | 대시보드에서 member_status=1만 카운트 (시스템 계정 제외) |

## 알려진 이슈

- 대시보드 사용자 수가 2로 표시됨 → `system` 내부계정 포함 (member_status=3). `WHERE member_status=1` 필터 추가 예정
- ANTHROPIC_API_KEY가 더미값(sk-ant-xxxxx) → 실제 키 입력 필요
- 회사/집 환경의 IP가 다름 → 배포 시 IP 치환 필요

---
*마지막 업데이트: 2026-03-31 (집 환경, v3.5)*
