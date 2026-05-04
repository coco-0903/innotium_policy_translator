# Policy Analyzer — 작업 핸드오프

> **이 파일을 읽는 Claude에게:** 이 문서는 다른 환경의 Claude 세션에서 작업을 이어받기 위한 컨텍스트입니다.
> 먼저 이 파일을 읽고, 필요하면 `README.md`, `app.py`, `db.py` 를 추가로 읽으세요.

---

## 현재 버전: v3.6 (Phase 2 완료)

## 프로젝트 요약

Innotium Policy Analyzer — Flask 웹앱으로 이노티움 6개 보안제품의 정책 JSON을 번역/시뮬레이션/진단하는 도구.
Claude AI(claude-sonnet-4-6) + MariaDB(innoplatform) 직접 연동.

## 완료된 작업

| 항목 | 상태 | 파일 |
|------|------|------|
| Gemini → Claude API 전환 | ✅ | app.py |
| MariaDB 직접 연동 + Connection Pooling | ✅ | db.py |
| 서버 배포 (Gunicorn + Nginx + systemd) | ✅ | 서버 /app/policy-analyzer/ |
| Frontend DB 조회 UI | ✅ | script.js, index.html |
| Frontend 로그 분석 탭 | ✅ | script.js, index.html |
| 대시보드 UI | ✅ | script.js, index.html, style.css |
| 매니저 ↔ Policy Analyzer 상호 링크 | ✅ | patch_main.py |
| Few-Shot 피드백 시스템 | ✅ | db.py, app.py, script.js |
| .env.example | ✅ | .env.example |
| 중간점검 보고서 (.docx) | ✅ | Policy_Analyzer_중간점검_보고서.docx |
| **Phase 2-1: 통합 정책 조립 (JOIN)** | ✅ | db.py, app.py |
| **Phase 2-2: 사용자/부서별 정책 조회** | ✅ | db.py, app.py, script.js |
| **Phase 2-3: 대시보드 member_status=1 필터** | ✅ | db.py |
| **Phase 2-4: 정책 변경 이력 타임라인** | ✅ | db.py, app.py, script.js |

## Phase 2 구현 상세

### Phase 2-1: 통합 정책 조립
- **엔드포인트:** `GET /api/policies/unified/<id>/full`
- **함수:** `get_unified_policy_full(policy_id)` in db.py
- **동작:** `tb_unified_agent_policy`의 FK 컬럼으로 각 제품 정책 JOIN 조립
- **UI:** DB 조회 탭에서 unified 정책 선택 시 정책 아이템에 조립 버튼(🔷) 표시

### Phase 2-2: 사용자/부서별 조회
- **엔드포인트:** `GET /api/users`, `GET /api/users/<id>/policies`
- **엔드포인트:** `GET /api/groups`, `GET /api/groups/<id>/policies`
- **테이블:** `tb_user_agent_policy`, `tb_group_agent_policy` JOIN `tb_unified_agent_policy`
- **UI:** DB 조회 탭 → "사용자별" / "부서별" 서브탭

### Phase 2-3: 대시보드 사용자 수 수정
- `WHERE member_status = 1` 추가 (system 계정 제외)

### Phase 2-4: 변경 이력 타임라인
- **엔드포인트:** `GET /api/timeline?limit=30`
- **함수:** `get_policy_timeline(limit)` — 전체 12개 정책 테이블 update_datetime 합산 정렬
- **UI:** DB 조회 탭 → "변경 이력" 서브탭

## 서버 환경 (2개)

### 집 환경 (2026-03-31 구성 완료)
```
SSH: root@172.30.1.44 (id_rsa 키 인증)
배포 경로: /app/policy-analyzer/
웹 접속: http://172.30.1.44:40010
매니저: http://172.30.1.44:40000
서비스: systemctl restart policy-analyzer
로그: /var/log/nginx/, /log/policy-analyzer/
```

### 회사 환경 (v3.5 상태 → v3.6으로 업그레이드 필요)
```
SSH: root@192.168.11.97
배포 경로: /app/policy-analyzer/
웹 접속: http://192.168.11.97:40010
매니저: http://192.168.11.97:40000
```

## 핵심 계정 정보 (별도 보관 필요)

- DB, 웹 관리자 비밀번호는 `.env` 파일에서 관리
- **중요:** 실제 비밀번호는 이 파일에 기재하지 않음 (보안)

## API 엔드포인트 전체 목록 (v3.6)

| 엔드포인트 | 메서드 | 설명 |
|-----------|--------|------|
| `/api/translate` | POST | 정책 번역 |
| `/api/simulate` | POST | 시뮬레이션 |
| `/api/diagnose` | POST | 진단 |
| `/api/dashboard` | GET | 대시보드 통계 |
| `/api/policies` | GET | 전체 정책 목록 |
| `/api/policies/<product>` | GET | 제품별 정책 목록 |
| `/api/policies/<product>/<id>` | GET | 정책 상세 |
| `/api/policies/unified/<id>/full` | GET | **[NEW]** 통합 정책 조립 |
| `/api/users` | GET | **[NEW]** 사용자 목록 |
| `/api/users/<id>/policies` | GET | **[NEW]** 사용자별 정책 |
| `/api/groups` | GET | **[NEW]** 부서 목록 |
| `/api/groups/<id>/policies` | GET | **[NEW]** 부서별 정책 |
| `/api/timeline` | GET | **[NEW]** 정책 변경 이력 |
| `/api/feedback` | POST | 피드백 저장 |
| `/api/logs/list` | GET | 로그 파일 목록 |
| `/api/logs/analyze` | POST | 로그 분석 |
| `/health` | GET | 서비스 상태 |

## 회사에서 v3.5 → v3.6 업그레이드 방법

```bash
# 서버에서
cd /app/policy-analyzer
git pull origin main
systemctl restart policy-analyzer
```

수동 배포 시:
```bash
scp app.py db.py static/index.html static/script.js static/style.css root@192.168.11.97:/app/policy-analyzer/
ssh root@192.168.11.97 "systemctl restart policy-analyzer"
```

## 알려진 이슈 / 주의사항

- Phase 2 JOIN은 `tb_unified_agent_policy`에 제품별 FK 컬럼 존재를 가정함
  → 실제 컬럼명이 다를 경우 `_UNIFIED_FK_MAP` (db.py) 수정 필요
- `tb_user_agent_policy`, `tb_group_agent_policy` 테이블 컬럼명도 실제 스키마 확인 필요
- ANTHROPIC_API_KEY 실제 키 입력 필요 (.env)

## 다음 작업 (Phase 3 후보)

| 우선순위 | 항목 |
|---------|------|
| 1 | DB 전용 읽기 계정 생성 (pa_reader) — 보안 |
| 2 | HTTPS 적용 (자체서명 인증서) |
| 3 | Gunicorn 전용 서비스 계정 생성 (root 탈피) |
| 4 | 정책 diff 비교 (두 정책 간 변경점 시각화) |
| 5 | Claude RAG → Fine-tuning 전환 |

---
*마지막 업데이트: 2026-04-01 (Phase 2 완료)*
