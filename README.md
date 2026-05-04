# Policy Analyzer — Innotium Security Platform

보안 정책 JSON을 AI로 번역·시뮬레이션·진단하는 내부 도구.
SecureZone, RansomCruncher, nPouch, innoMark, LizardBackup, innoECM 6개 제품 지원.

---

## 현재 버전: v3.0

### 변경 이력

| 버전 | 주요 변경 |
|------|----------|
| v1.0 | 최초 개발 — JSON 복붙 → 번역 |
| v2.0 | 시뮬레이터 + 진단 탭 추가 |
| v2.5 | UI 리디자인, 파일 드래그앤드롭 |
| v3.0 | **Claude AI 전환**, **MariaDB 직접 연동**, 서버 배포 |

---

## 아키텍처

```
innotium_policy_translator/
├── app.py              # Flask 라우트 + Claude AI 프롬프트 + 도메인 지식
├── db.py               # MariaDB 연동 (12개 제품 테이블 매핑)
├── parser.py           # 입력 전처리 파이프라인
├── requirements.txt
├── .env.example        # 환경변수 템플릿
├── DEPLOYMENT_PLAN.md  # 서버 배포 레시피
└── static/
    ├── index.html
    ├── script.js       # 프론트엔드 (파일 업로드, API 호출, Markdown 렌더링)
    └── style.css
```

### 요청 흐름

```
브라우저 (index.html)
    └─ POST /api/translate|simulate|diagnose
           └─ parser.py: 입력 정제 → JSON 추출 → 제품 감지 → 마스킹
                  └─ app.py: POLICY_KNOWLEDGE + 프롬프트 조합
                         └─ Claude API (claude-sonnet-4-6)
                                └─ Markdown 응답 → 브라우저 렌더링
```

---

## API 엔드포인트

| 엔드포인트 | 메서드 | 기능 |
|-----------|--------|------|
| `/api/translate` | POST | 정책 JSON → 자연어 설명 |
| `/api/simulate` | POST | 정책 적용 시 동작 예측 |
| `/api/diagnose` | POST | 보안 감사 (점수/100 + 취약점 목록) |
| `/api/dashboard` | GET | 제품별 정책 수 + 사용자/부서 현황 |
| `/api/policies` | GET | 전체 정책 목록 (제품별) |
| `/api/policies/<product>/<id>` | GET | 특정 정책 상세 JSON |
| `/api/logs/list` | GET | 서버 로그 파일 목록 |
| `/api/logs/analyze` | POST | 로그 파일 AI 분석 |
| `/health` | GET | 서비스 상태 확인 |

모든 POST는 `{ "policy": "<raw text or JSON>" }` 수신 → `{ "result": "<markdown>" }` 반환.

---

## 로컬 개발 환경

```bash
cd innotium_policy_translator

pip install -r requirements.txt

# .env 생성
cp .env.example .env
# .env 파일에서 ANTHROPIC_API_KEY 설정

python app.py
# http://localhost:5000
```

---

## 서버 배포 (Rocky Linux 9.7)

서버 정보:
- IP: 192.168.11.97
- 서비스 포트: 40010 (Nginx → Gunicorn 5000)
- 앱 경로: /app/policy-analyzer/

```bash
# 서버 접속
ssh root@192.168.11.97

# 앱 배포
cd /app/policy-analyzer
git pull
pip install -r requirements.txt
systemctl restart policy-analyzer

# 상태 확인
systemctl status policy-analyzer
journalctl -u policy-analyzer -n 50
```

자세한 배포 절차는 `DEPLOYMENT_PLAN.md` 참고.

---

## 지원 제품 & DB 테이블 매핑

| 제품 | DB 테이블 |
|------|----------|
| SecureZone | tb_secure_zone_agent_policy |
| SecureZone ACL | tb_secure_zone_access_control_policy |
| ControlSuite | tb_control_suite |
| RansomCruncher | tb_ransom_cruncher_detect_policy |
| RansomCruncher RDP | tb_ransom_cruncher_rdp_policy |
| nPouch | tb_npouch_policy |
| nPouch Origin | tb_npouch_origin_protect_policy |
| innoMark | tb_inno_mark_policy |
| innoMark RDP | tb_inno_mark_rdp_policy |
| LizardBackup | tb_lizard_backup_policy |
| LizardBackup Agent | tb_lizard_agent_policy |
| Unified | tb_unified_agent_policy |

---

## 개발 로드맵

### Phase 1 — 기능 완성 (현재)

- [x] Claude API 전환 (Gemini → claude-sonnet-4-6)
- [x] MariaDB 직접 연동 (db.py)
- [x] 서버 배포 (Gunicorn + Nginx + systemd)
- [x] 매니저 서버 ↔ Policy Analyzer 상호 링크 버튼
- [ ] **Frontend DB 조회 UI** — 제품 선택 → 정책 목록 → 클릭 → 바로 분석
- [ ] **Frontend 로그 분석 탭** — 서버 로그 파일 트리 → AI 분석

### Phase 2 — DB 고도화

- [ ] 통합 정책 조립 — 에이전트에게 내려가는 것과 동일한 형태로 JOIN 조립
  - SecureZone = agent_policy + control_suite + secure_drive_template + process_template
  - RansomCruncher = detect_policy + rdp_policy + process_list
  - nPouch = policy + origin_protect + privacy_items
- [ ] 사용자/부서별 정책 조회 (tb_user_agent_policy JOIN)
- [ ] 정책 변경 이력 타임라인 (create/update_datetime 기반)
- [ ] Connection Pooling (현재 매 요청마다 연결 생성)

### Phase 3 — AI 학습 능력 확보

#### Step 3-1: Few-Shot 예제 축적 (즉시 시작 가능)

분석 결과에 평점 버튼 추가 → 좋은 예시를 DB에 저장 → 프롬프트에 자동 삽입.

```python
# 분석 결과 저장 구조
CREATE TABLE policy_analysis_examples (
    id INT AUTO_INCREMENT PRIMARY KEY,
    product VARCHAR(50),
    policy_json TEXT,
    analysis_result TEXT,
    feature ENUM('translate', 'simulate', 'diagnose'),
    rating TINYINT,  -- 1~5
    created_at DATETIME DEFAULT NOW()
);
```

효과: 실제 사례 기반으로 Claude 분석 정확도 향상, 데이터 많을수록 증가.

#### Step 3-2: RAG (검색 증강 생성) — 데이터 100건+ 시

```
정책 JSON → 벡터 임베딩 (Claude Embeddings) → ChromaDB 저장
새 정책 입력 → 유사 정책 top-5 검색 → system prompt에 "참고 사례" 로 주입
```

구현 스택:
- `anthropic` 임베딩 API 또는 `sentence-transformers`
- `chromadb` (로컬) 또는 `pgvector` (PostgreSQL 확장)

#### Step 3-3: Fine-Tuning — 데이터 500건+ 시

| 항목 | 내용 |
|------|------|
| 대상 모델 | Llama 3 또는 Mistral (오픈소스) |
| 방법 | LoRA / QLoRA (4-bit 양자화) |
| 데이터 | (정책 JSON, 분석 결과) 쌍 500건+ |
| 필요 자원 | GPU 서버 (A100 또는 RTX 4090 급) |
| 장점 | API 비용 없음, 도메인 특화 |
| 참고 | Claude는 Anthropic API 파인튜닝 불가 (2025 기준) |

**추천 단계:**
1. 즉시 → Few-Shot 피드백 버튼 추가
2. 100건+ → ChromaDB RAG 도입
3. 500건+ → LoRA 파인튜닝 검토

### Phase 4 — 안정성 & 운영

- [ ] CORS 도메인 제한 (192.168.11.97만 허용)
- [ ] 요청 크기 제한 (Flask max_content_length)
- [ ] Rate limiting (flask-limiter)
- [ ] 구조화 에러 로깅 (JSON 포맷)
- [ ] Claude API 타임아웃 설정
- [ ] 분석 결과 PDF/DOCX 내보내기
- [ ] 정책 비교 기능 (A정책 vs B정책 diff)

---

## 서버 업데이트 대응

매니저 서버 프론트엔드(`main.html`) 업데이트 시 "Policy Analyzer" 연결 버튼이
덮어씌워질 수 있음. 재패치 방법:

```bash
ssh root@192.168.11.97
cd /project/apiFront
python3 /app/policy-analyzer/patch_main.py
```

`patch_main.py`는 `user/main.html`과 `manager/main.html`의 `</body>` 직전에
Policy Analyzer 플로팅 버튼을 자동 삽입함 (백업 `.bak` 생성 후 패치).

---

## 환경변수

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `ANTHROPIC_API_KEY` | Claude API 키 (필수) | — |
| `DB_HOST` | MariaDB 호스트 | 127.0.0.1 |
| `DB_PORT` | MariaDB 포트 | 43306 |
| `DB_USER` | DB 사용자 | root |
| `DB_PASS` | DB 비밀번호 | — |
| `DB_NAME` | DB 이름 | innoplatform |

---

## 기술 스택

- **Backend**: Python 3.9 + Flask 3.x + Gunicorn
- **AI**: Anthropic Claude (claude-sonnet-4-6), temperature 0.3
- **DB**: MariaDB 10.x (pymysql, port 43306)
- **Frontend**: Vanilla HTML/CSS/JS + marked.js (Markdown 렌더링)
- **Infra**: Rocky Linux 9.7, Nginx 1.20.1, systemd
