# Policy Analyzer 고도화 & 매니저 서버 배포 레시피

## 프로젝트 개요

**Innotium Policy Analyzer** — Flask 웹앱으로, 이노티움 6개 보안제품(SecureZone, RansomCruncher, nPouch, innoECM, LizardBackup, innoMark)의 정책 JSON을 번역/시뮬레이션/진단하는 도구.

현재 상태: 로컬 개발용, Gemini AI 기반, 수동 JSON 복붙 방식.
목표: 실제 매니저 서버에 배포 + Claude API 전환 + MariaDB 직접 연동.

---

## 매니저 서버 환경 (SSH 검증 완료 2026-03-30)

```
IP: 192.168.11.97
SSH: root / Qwert (port 22)
DB:  root / Qwert (port 43306) — DB명: innoplatform, innoplatformlog
```

| 항목 | 값 |
|------|-----|
| OS | Rocky Linux 9.7 |
| Python | 3.9.25 |
| Java | JDK 1.8.0_192 |
| Nginx | 1.20.1 (포트: 80, 40000, 40001) |
| MariaDB | 10.11.15 (포트: **43306**) |
| Redis | 7.2.11 (포트: **46379**, bind 127.0.0.1) |
| Tomcat | 9.0.102 (포트: 8101, 8001) |

### 디렉토리 구조
```
/app/           → tomcat, java, redis (서비스별 소유자)
/project/       → apiFront, apiServer (innoplatform 소유)
/log/           → catalina, nginx
/cache/         → agentLog, ecmData
/data/          → ecmData, npouchData
```

### 방화벽 오픈 포트
40000/tcp, 40001/tcp, SSH, NTP — Policy Analyzer용 포트 추가 필요

### DB 핵심 정책 테이블 (innoplatform DB, 200+개 테이블)
```
tb_secure_zone_agent_policy        (35컬럼) — SecureZone 에이전트 정책
tb_secure_zone_access_control_policy        — SecureZone 접근제어
tb_control_suite                   (15컬럼) — 제어스위트
tb_ransom_cruncher_detect_policy   (28컬럼) — 랜섬크런처 탐지
tb_ransom_cruncher_rdp_policy               — RC RDP
tb_npouch_policy                   (31컬럼) — 엔파우치
tb_npouch_origin_protect_policy             — 원본보호
tb_inno_mark_policy                (18컬럼) — 이노마크
tb_inno_mark_rdp_policy                     — IM RDP
tb_lizard_backup_policy            (17컬럼) — 리자드백업
tb_lizard_agent_policy                      — LB 에이전트
tb_unified_agent_policy            (8컬럼)  — 통합정책
tb_users, tb_groups                         — 사용자/부서
```

**중요:** DB 컬럼은 `snake_case` (예: `sz_agent_policy_id`), JSON API는 `camelCase` (예: `szAgentPolicyId`) → 변환 필요

**현재 데이터:** 초기 셋업 상태. 정책 테이블 모두 0건, 통합정책 1건, 사용자 2명, 부서 2개.

---

## 현재 프로젝트 파일 구조

```
innotium_policy_translator/
├── app.py           ← Flask 라우트 + Gemini AI 호출 + POLICY_KNOWLEDGE (~2500줄 KB)
├── parser.py        ← 전처리 파이프라인 (JSON 추출, 제품 자동 탐지, 중복제거, 마스킹)
├── requirements.txt ← flask, flask-cors, google-genai, python-dotenv
├── .env             ← GEMINI_API_KEY
└── static/
    ├── index.html   ← 메인 페이지 (좌: 입력, 우: 결과)
    ├── script.js    ← 프론트엔드 로직 (파일업로드, API호출, 마크다운렌더링)
    └── style.css    ← 스타일
```

### app.py 핵심 구조
- 17~24줄: google-genai SDK 자동 감지 (신/구 버전)
- 38~49줄: Gemini API 설정 (모델: gemini-2.5-flash, temp: 0.3)
- 53~74줄: `call_gemini()` — AI 호출 함수
- 80~731줄: `POLICY_KNOWLEDGE` — 6개 제품 필드 정의 + 80개 진단 규칙 (RAG KB)
- 738~830줄: 3개 프롬프트 (TRANSLATE_PROMPT, SIMULATE_PROMPT, DIAGNOSE_PROMPT)
- 라우트: `/api/translate`, `/api/simulate`, `/api/diagnose` (POST), `/health` (GET)

### parser.py 파이프라인
1. `detect_input_type()` → 2. `extract_json_from_log()` → 3. `detect_product()` → 4. `unwrap_policy()` → 5. `deduplicate()` → 6. `compress_and_mask()`

---

## 작업 계획 (순서대로)

### Step 1: Gemini → Claude API 교체

**수정 파일:** `app.py`, `requirements.txt`, `.env`

- `google-genai` 제거 → `anthropic` SDK 추가
- `call_gemini()` → `call_claude()` 교체
- 모델: `claude-sonnet-4-6` (빠르고 정확)
- `POLICY_KNOWLEDGE`를 system prompt로, 사용자 입력을 user message로 분리
- `.env`: `GEMINI_API_KEY` → `ANTHROPIC_API_KEY`
- temperature 0.3 유지
- requirements.txt: `google-genai` → `anthropic`

### Step 2: DB 연동 모듈

**신규 파일:** `db.py`
**수정 파일:** `app.py` (새 엔드포인트), `requirements.txt`

- `pymysql` 사용, 연결 정보 `.env`에서 로드
- DB 연결: `127.0.0.1:43306` / `innoplatform`
- snake_case → camelCase 자동 변환 유틸
- 새 엔드포인트:
  - `GET /api/policies` — 전체 정책 목록 (제품별)
  - `GET /api/policies/<product>/<id>` — 특정 정책 JSON
  - `GET /api/dashboard` — 제품별 정책 수, 사용자/부서 현황
- `.env` 추가: `DB_HOST=127.0.0.1`, `DB_PORT=43306`, `DB_USER=root`, `DB_PASS=Qwert`, `DB_NAME=innoplatform`

### Step 3: 로그 파일 읽기 기능

**수정 파일:** `app.py`

- 새 엔드포인트:
  - `GET /api/logs/list` — 허용된 디렉토리의 로그 파일 목록
  - `POST /api/logs/analyze` — 로그 파일 경로 → 내용 읽어서 분석
- 허용 경로: `/log/catalina/`, `/cache/agentLog/`, `/log/nginx/`
- 보안: 경로 탐색 제한 (path traversal 방지)

### Step 4: Frontend 개선

**수정 파일:** `static/index.html`, `static/script.js`, `static/style.css`

- "DB에서 정책 불러오기" 버튼 + 드롭다운 (제품 선택 → 정책 목록 → 선택 → 자동 로드)
- "서버 로그 분석" 탭 추가
- 대시보드 영역 (정책 현황 요약)

### Step 5: 서버 배포

서버에서 실행할 명령어:

```bash
# 1. pip 확인/설치
dnf install python3-pip -y

# 2. 앱 디렉토리
mkdir -p /app/policy-analyzer
mkdir -p /log/policy-analyzer

# 3. 코드 업로드 (scp)
# scp -r ./innotium_policy_translator/* root@192.168.11.97:/app/policy-analyzer/

# 4. venv + 의존성
cd /app/policy-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt gunicorn

# 5. .env 생성
cat > .env << 'EOF'
ANTHROPIC_API_KEY=sk-ant-xxxxx
DB_HOST=127.0.0.1
DB_PORT=43306
DB_USER=root
DB_PASS=Qwert
DB_NAME=innoplatform
EOF

# 6. Systemd 서비스
cat > /etc/systemd/system/policy-analyzer.service << 'EOF'
[Unit]
Description=Policy Analyzer (Flask + Claude AI)
After=network.target mariadb.service

[Service]
Type=simple
User=root
WorkingDirectory=/app/policy-analyzer
Environment=PATH=/app/policy-analyzer/venv/bin
ExecStart=/app/policy-analyzer/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:5000 --access-logfile /log/policy-analyzer/access.log --error-logfile /log/policy-analyzer/error.log app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 7. Nginx 리버스 프록시
cat > /etc/nginx/conf.d/policy-analyzer.conf << 'EOF'
server {
    listen 40010;
    server_name _;
    access_log /log/nginx/policy-analyzer-access.log;
    error_log /log/nginx/policy-analyzer-error.log;
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    location /static/ {
        alias /app/policy-analyzer/static/;
        expires 1d;
    }
}
EOF
mkdir -p /log/nginx/

# 8. 방화벽
firewall-cmd --permanent --zone=public --add-port=40010/tcp
firewall-cmd --reload

# 9. 시작
systemctl daemon-reload
systemctl enable policy-analyzer
systemctl start policy-analyzer
systemctl restart nginx
```

### Step 6: 검증

```bash
# 서비스 상태
systemctl status policy-analyzer

# 헬스체크
curl http://localhost:5000/health
curl http://localhost:40010/health

# DB 연동 테스트
curl http://localhost:40010/api/dashboard
```

브라우저: `http://192.168.11.97:40010` 접속하여 UI 확인.

---

## 주의사항

1. **Anthropic API Key** 필요 — 서버가 외부 인터넷 접근 가능해야 함
2. **DB 비밀번호** `.env`에만 저장, 코드에 하드코딩 금지
3. **parser.py는 수정하지 않음** — 기존 전처리 로직 그대로 유지
4. **POLICY_KNOWLEDGE는 유지** — Claude API에서 system prompt로 활용
5. **기존 3개 기능(번역/시뮬/진단) 유지** — DB 연동은 추가 기능
