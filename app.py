"""
╔══════════════════════════════════════════════════════════════╗
║  Policy Analyzer v3.0 — 보안 정책 번역기 & 시뮬레이터        ║
║  Innotium Security Platform v11                              ║
║  6개 제품 통합 Knowledge Base (매뉴얼 기반 강화)               ║
║  Powered by Claude AI + RAG                                  ║
╚══════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
import os
import re
import json
import json as _json
import logging
import logging.handlers
import time
from datetime import datetime
from zoneinfo import ZoneInfo
from parser import parse_input
import anthropic

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

CORRECTIONS_FILE = os.path.join(os.path.dirname(__file__), 'corrections.json')


def load_corrections():
    """저장된 오답 수정 내역 로드 (최근 10개)"""
    if not os.path.exists(CORRECTIONS_FILE):
        return []
    try:
        with open(CORRECTIONS_FILE, 'r', encoding='utf-8') as f:
            data = _json.load(f)
        return data[-10:] if len(data) > 10 else data
    except Exception:
        return []


def save_correction(question, wrong_answer, correction, structured):
    """오답 수정 내역 저장"""
    corrections = []
    if os.path.exists(CORRECTIONS_FILE):
        try:
            with open(CORRECTIONS_FILE, 'r', encoding='utf-8') as f:
                corrections = _json.load(f)
        except Exception:
            corrections = []
    corrections.append({
        'id': str(int(time.time())),
        'question': question,
        'wrong_answer': wrong_answer[:500],
        'structured': structured,
        'timestamp': datetime.now(ZoneInfo('Asia/Seoul')).isoformat()
    })
    with open(CORRECTIONS_FILE, 'w', encoding='utf-8') as f:
        _json.dump(corrections, f, ensure_ascii=False, indent=2)


# ═══════════════════════════════════════════════════
# 로깅 설정
# ═══════════════════════════════════════════════════
LOG_DIR = os.getenv('LOG_DIR', './logs')
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger('policy_analyzer')
logger.setLevel(logging.INFO)

_log_file = os.path.join(LOG_DIR, 'app.log')
_handler = logging.handlers.RotatingFileHandler(
    _log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding='utf-8'
)
_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s %(message)s', datefmt='%Y-%m-%dT%H:%M:%S'
))
logger.addHandler(_handler)
logger.addHandler(logging.StreamHandler())

# ═══════════════════════════════════════════════════
# Flask 앱 설정
# ═══════════════════════════════════════════════════
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB

_ALLOWED_ORIGINS = os.getenv(
    'ALLOWED_ORIGINS',
    'http://192.168.11.97:40000,http://192.168.11.97:40001,'
    'http://192.168.11.97:40010,http://127.0.0.1:5000,http://localhost:5000'
).split(',')
CORS(app, origins=[o.strip() for o in _ALLOWED_ORIGINS])

# Rate limiting
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["300 per hour"],
        storage_uri="memory://",
    )
    _limiter_available = True
except ImportError:
    _limiter_available = False
    class _NoopLimiter:
        def limit(self, *a, **kw):
            return lambda f: f
    limiter = _NoopLimiter()
    logger.warning("flask-limiter 미설치 — rate limiting 비활성화")

# ═══════════════════════════════════════════════════
# Claude API 설정
# ═══════════════════════════════════════════════════
API_KEY = os.getenv('ANTHROPIC_API_KEY', '')
MODEL_NAME      = 'claude-sonnet-4-6'        # 번역/진단/분석용 (고품질)
CHAT_MODEL_NAME = 'claude-haiku-4-5-20251001' # 챗봇용 (50K토큰/분, 저비용)

client = anthropic.Anthropic(api_key=API_KEY, timeout=120.0)

logger.info(f"Policy Analyzer v3.0 시작 — 모델: {MODEL_NAME}")
print(f"[✓] Claude 모델: {MODEL_NAME}")
print("[✓] Policy Analyzer v3.0 — 6개 제품 통합 (매뉴얼 기반 KB)")


def call_claude(system_prompt, user_message, model=None):
    """Claude API 호출. model 미지정 시 MODEL_NAME(Sonnet) 사용."""
    use_model = model or MODEL_NAME
    try:
        logger.info(f"Claude API 호출 — 모델: {use_model}, 입력 길이: {len(user_message)}")
        response = client.messages.create(
            model=use_model,
            max_tokens=8192,
            temperature=0.3,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}]
        )
        result = response.content[0].text
        logger.info(f"Claude API 완료 — 출력 길이: {len(result)}")
        return result
    except anthropic.APITimeoutError:
        logger.error(f"Claude API 타임아웃 — 모델: {use_model}")
        return "AI 응답 시간 초과. 입력이 너무 크거나 서버 부하가 높습니다. 잠시 후 재시도해주세요."
    except Exception as e:
        logger.error(f"Claude API 오류: {e}")
        return f"AI 호출 오류: {str(e)}"


def _build_few_shot(feature: str, product: str = '') -> str:
    """DB에서 좋은 평가 예시를 가져와 few-shot 블록 생성"""
    try:
        examples = get_feedback_examples(feature, product, limit=3)
        if not examples:
            return ""
        parts = ["[참고 사례 — 아래는 실제 좋은 분석 예시입니다]\n"]
        for i, ex in enumerate(examples, 1):
            parts.append(f"--- 예시 {i} ---\n입력:\n{ex['policy_json'][:800]}\n\n출력:\n{ex['analysis_result'][:1200]}\n")
        parts.append("--- 위 예시 참고하여 분석하세요 ---\n\n")
        return '\n'.join(parts)
    except Exception:
        return ""


# ═══════════════════════════════════════════════════
# 정책 지식 베이스 (RAG Knowledge Base) — 6개 제품 통합
# ═══════════════════════════════════════════════════
POLICY_KNOWLEDGE = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📚 이노티움 6개 제품 정책 필드 정의서 (Knowledge Base v2.5 — 매뉴얼 기반)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 시스템 구조
이노티움 보안 솔루션은 **서버-클라이언트(에이전트)** 구조입니다.
- 서버(Rocky Linux): MariaDB + Nginx + Tomcat + Redis 기반 중앙관리매니저
- 클라이언트(Windows): 에이전트가 정책을 수신하여 PC에 보안 통제 적용
- 통합설치 프로그램으로 6개 에이전트 선택 설치, 에이전트 서버주소(ip:port) 지정
- 정책은 JSON 형태로 서버에 저장되며, 에이전트가 갱신주기마다 수신하여 동작

## ★ 정책 적용 우선순위 (6개 제품 공통)
사용자 개별정책 > 사용자 통합정책 > 부서 개별정책 > 부서 통합정책
- 통합정책: 여러 제품 정책을 하나로 묶어 부여 (System Management > 전역정책 관리)
- 개별정책: 제품별 App Setting에서 생성한 정책을 직접 할당
- 기본정책으로 설정된 통합정책은 미할당 사용자에게도 자동 적용
- 부서는 트리구조(상위/하위), 사용자는 다중 부서 소속 가능

## 공통 필드 (모든 제품)
- `status`: CREATE(활성,code:1) / DELETE(비활성,code:2)
- `createDatetime`/`updateDatetime`: 생성/수정 일시
- `createUserName`/`updateUserName`: 생성/수정자
- `assignPolicyType`: 정책 할당 유형 (null=미할당)
- 에이전트 명령: 업데이트, 제거, 무결성검사 (대기→명령수신→완료)
- 로그인 잠금: 5회 실패 → 5분 잠금, 비밀번호 9~20자(대/소/특수 필수)

## 제품 목록
1. **SecureZone(시큐어존)** — 엔드포인트 보안 (보안드라이브, 프로세스/USB/출력 제어)
2. **RansomCruncher(랜섬크런처)** — 랜섬웨어 탐지/차단/롤백
3. **nPouch(엔파우치)** — 파일 암호화 반출 + 원본보호
4. **innoECM** — 문서중앙화 (중앙 저장소 + 에이전트 드라이브)
5. **LizardBackup(리자드백업)** — 파일 백업/복구
6. **innoMark(이노마크)** — 화면/출력 워터마크 + 캡처 방지

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## ① SecureZone (시큐어존) — 엔드포인트 보안(영역암호화 DRM)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Envelope(영역암호화) 방식 차세대 DRM. 기존 Hooking방식 단점 보완, 기존 환경 변화 최소화.
PC에 보안드라이브(암호화 가상디스크)를 생성하여 파일 보호. USB·프로세스·출력·클립보드·네트워크 제어.
문서 외부 반출 시 결재 시스템(결재라인, 자가결재, 회수)을 통해 승인 후 반출.

### 정책 구성 계층:
시큐어존 정책 = 시큐어드라이브 템플릿 + 제어스위트 + 프로세스 통제
접근제어 정책 = 독립(드라이브 숨김/차단, CMD/레지스트리/USB 제어)
결재 = 결재라인 관리 + 결재문서(기안→대기→승인/반려)

### 에이전트 정책 (Agent Policy) — 최상위 정책
| 필드 | 설명 | 보안 |
|------|------|------|
| szAgentPolicyName | 정책 이름 | - |
| szAgentPolicyType | DEFAULT(일반)/TAKEOUT_DEFAULT(반출기본) | 🟠 |
| secureDriveTemplateId | 연결된 보안드라이브 템플릿 ID | 🔴 |
| controlSuiteId | 연결된 제어스위트 ID | 🔴 |
| isTakeoutDriveBlock | **반출드라이브 차단** — true면 파일 반출 불가 | 🔴 |
| isPrintUse / isPrint | 출력 제어 사용/허용(0:차단,1:허용) | 🟠 |
| isAllowDenyProcessUse | 프로세스 허용/차단 사용 | 🔴 |
| isAllowDenyProcess | 프로세스 모드(0:미사용,1:허용목록,2:차단목록) | 🔴 |
| isBlockExecuteProcess | 특정 프로세스 실행 차단 | 🔴 |
| isExceptProcess | 예외 프로세스 사용 | 🟡 |
| isManageFolder | 관리폴더 — 지정 폴더만 접근 | 🟠 |
| isSyncFolder | 서버 폴더 동기화 | 🟡 |
| isWatchFile / isWatchFolder | 파일/폴더 변경 감시 | 🟠 |
| isWatchFileExtention / isWatchFileHeader | 확장자/헤더 감시 필터 | 🟡 |
| isShowAgentShutdownMenu | 에이전트 종료 메뉴(true=종료가능→보안약화) | 🟡 |
| isShowEmergencyCodeMenu | 비상코드 메뉴 | 🟡 |
| isOfflineUse | 오프라인 보안드라이브 사용 허용 | 🟠 |
| isLogin | 로그인 필요 | 🟡 |
| secureDriveBlockTime | 보안드라이브 차단 시간(분), 0=즉시 | 🟠 |

### 템플릿 (Template) — 보안드라이브 물리 구성
| 필드 | 설명 |
|------|------|
| szTemplateType | SECURE_DRIVE(보안)/SHORTCUT(바로가기) |
| secureDriveLetter / secureDriveLabel | 보안드라이브 문자/레이블 |
| takeoutDriveLetter / takeoutDriveLabel | 반출드라이브 문자/레이블 |
| takeoutDriveQuota | 반출드라이브 용량(MB), 0=무제한 |
| isTakeoutDrivePathHide / isTakeoutDrivePathAccessDeny | 반출 경로 숨김/차단 |
| isRegistEcmDrive | ECM 드라이브 등록 여부 |
※ 보안드라이브 생성위치의 드라이브 여유용량이 충분해야 함 (가상디스크 파일 생성됨)

### 프로세스 템플릿 — 보안드라이브 접근 프로세스 제어
| 프로세스 타입 | 동작 |
|------------|------|
| 허용(화이트리스트) | 등록된 프로세스만 보안드라이브(S:) 읽기/쓰기 가능, 미등록=차단 |
| 거부(블랙리스트) | 등록된 프로세스를 보안드라이브 접근 차단 |
- 프로세스 식별: 이름 + 전자서명 + SHA2 + 실행경로
- 태그로 프로세스 그룹핑 가능 (제어스위트·프로세스 템플릿에서 사용)

### 특수폴더 템플릿 — 폴더 리디렉션
| 용도 | 동작 |
|-----|------|
| 바로가기 | 원본위치의 바로가기를 대상위치(보안드라이브)에 생성 |
| 레지스트리 변경 | 레지스트리 경로값을 보안드라이브 경로로 변경 |

### 폴더동기화 템플릿 — 원본↔대상 자동 동기화
- 확장자 포함/제외 필터 지원

### 제어스위트 (Control Suite) — 세부 통제 규칙
| 필드 | 설명 | 보안 |
|------|------|------|
| isClipboardRestrict | **클립보드 제한** — 보안↔일반 복붙 차단 | 🔴 |
| isNetwork | **네트워크 제어** — 통신 제한 | 🔴 |
| isAllowExtension | **확장자 저장 제한 모드** — true=지정 확장자를 보안드라이브 이외 경로에 저장 차단 / false=지정 확장자만 보안드라이브 이외 경로에 저장 허용 | 🟠 |
| controlExtension | **제어 대상 확장자 목록** (`;` 구분자) — ⚠️ 방향 주의: 이 목록의 확장자는 **보안드라이브(S:) 이외의 일반 경로에 저장이 차단**됨. 즉 해당 파일은 반드시 보안드라이브에만 저장해야 함. "S:에 저장 금지"가 아니라 "S: 밖에 저장 금지"임. `.1`=전체 확장자 의미. | 🟠 |
| isHeaderCheck | 파일 헤더 검사(위변조 탐지) | 🟠 |
| isSignExcept / signExcept | **디지털서명 예외** — isSignExcept=true일 때 signExcept 목록의 서명 프로세스는 **보안드라이브 이외 영역 접근을 허용** (제어 제외). 즉 해당 서명 프로세스는 일반 드라이브에도 파일 읽기/쓰기 가능 | 🟡 |
| controlSuiteProcessList / controlSuiteProcessTagList | 프로세스/태그 제어 목록 | 🔴 |
| controlSuiteWebRestrictList | 웹 제한 목록 | 🟠 |

### 접근제어 정책 (Access Control) — Windows 시스템 기능 제어
| 필드 | 설명 | 보안 |
|------|------|------|
| isAccessControl | 접근제어 활성화 | 🔴 |
| isCmd | **CMD 허용 여부** ⚠️ true=CMD **사용 가능**(허용) / false=CMD **차단** | 🟠 |
| isControlPanel | **제어판 허용 여부** ⚠️ true=제어판 **사용 가능**(허용) / false=제어판 **차단** | 🟠 |
| isRegedit | **Regedit 허용 여부** ⚠️ true=레지스트리 편집기 **사용 가능**(허용) / false=차단 | 🟠 |
| isMmc | **MMC/Gpedit 허용 여부** ⚠️ true=MMC·그룹정책 편집기 **사용 가능**(허용) / false=차단 | 🟠 |
| isHideExplorerRecent | 탐색기 최근 항목 숨김 | 🟡 |
| pickHideDrive | 숨길 드라이브(예:"D,E") | 🟠 |
| pickDenyDrive | 접근 차단 드라이브 | 🔴 |
| pickExceptDrive | 예외 드라이브 | 🟡 |
| usbControlAuth | USB(0:미사용,1:읽기전용,2:차단) | 🔴 |

### 동작 상세 — 보안 계층 구조
시큐어존은 **3중 보호 계층**으로 동작:
1. **DRM (Envelope 영역암호화)**: 보안드라이브(S:) 자체가 암호화 컨테이너 — 외부 복사 시 자동 암호화 해제 불가
2. **Hooking 제어**: 클립보드·출력·스크린샷 API 후킹으로 보안드라이브 데이터 유출 차단
3. **Sandboxing (프로세스 템플릿)**: 허용된 프로세스만 보안드라이브 접근 — 알 수 없는 앱은 자동 차단

### 동작 상세 — 보안드라이브 생성 방식
- **SECURE_DRIVE**: 지정 드라이브 문자(예: S:)로 암호화 가상디스크 마운트
- **SHORTCUT**: 기존 폴더를 보안드라이브 바로가기로 등록 (폴더 리디렉션)
- 보안드라이브 실체: 로컬 HDD에 암호화된 단일 파일(.szone 등)로 존재 → 충분한 여유 용량 필요
- 오프라인 사용(`isOfflineUse=true`): 네트워크 단절 상태에서도 보안드라이브 접근 허용

### 동작 상세 — 네트워크 제어
| 제어 방식 | 설정 위치 | 설명 |
|----------|----------|------|
| IP 화이트리스트 | 제어스위트 > isNetwork | 허용 IP 목록만 통신 허용, 나머지 차단 |
| IP 블랙리스트 | 제어스위트 > isNetwork | 차단 IP 목록만 차단, 나머지 허용 |
| URL 필터링 | 제어스위트 > controlSuiteWebRestrictList | 특정 URL 접근 제한 |
- 네트워크 제어는 보안드라이브 내 파일을 외부로 전송하는 경로를 제한하는 목적

### 동작 상세 — 프로세스 식별 방식
프로세스 4중 검증 (하나라도 불일치 시 차단):
1. **파일명**: 프로세스 실행파일명 (예: excel.exe)
2. **전자서명**: 코드서명 인증서 발급사 (예: Microsoft Corporation)
3. **SHA2 해시**: 실행파일 해시값 (버전 업그레이드 시 재등록 필요!)
4. **실행경로**: 설치 경로 (예: C:\\Program Files\\Microsoft Office\\...)
→ SHA2 해시 등록 후 Office 업데이트가 되면 해시값이 바뀌어 차단될 수 있음 — 업데이트 후 프로세스 재등록 주의

### 동작 상세 — USB 제어 (usbControlAuth)
| 값 | 동작 |
|----|------|
| 0 | 미사용 — USB 제어 없음 |
| 1 | **읽기전용** — USB 데이터 읽기만 허용, 쓰기(복사) 차단 |
| 2 | **완전차단** — USB 마운트 자체 차단 |
- 읽기전용(1)이 실무에서 가장 많이 사용 (자료 반입은 허용, 반출 차단)

### 동작 상세 — 반출 프로세스 (결재)
보안드라이브 파일 외부 반출 시:
1. 사용자 → 반출 요청 (파일 선택 + 사유)
2. 결재선 승인 (순차 또는 일괄)
3. 승인 완료 → 반출드라이브(T:)에 복호화된 파일 생성 → 정해진 기간 후 자동 삭제
4. 자가결재: 사용자 본인이 직접 승인 가능 (정책에서 허용 시)
5. 회수: 승인된 반출 파일을 관리자가 강제 회수 가능

### 동작 상세 — ECM 연동 포인트
- 에이전트 정책의 `isRegistEcmDrive=true` → ECM 드라이브를 보안드라이브로 등록
- 이노ECM 파일을 시큐어존 보안드라이브 정책 범위 안에서 접근 제어
- LizardBackup 원격저장소 프로토콜에서 innoECM 선택 → ECM 서버를 백업 저장소로 사용 가능

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## ② RansomCruncher (랜섬크런처) — 랜섬웨어 탐지/차단
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

랜섬웨어 비정상 파일 암호화를 실시간 탐지·차단, 피해 파일 자동 롤백(복구).

### 3단계 탐지 체계:
1. **소프트웨어 인증**: 프로세스 전자서명 유효성 검사 → 미통과 시 감시 프로세스로 분류·차단
2. **행위기반 탐지**: 파일 변조 행위 실시간 감시 → 임계치 초과 시 차단
3. **리스트기반 탐지**: 이미 차단된/공통 차단 프로세스 실행 즉시 차단

### 행위기반 탐지등급 상세:
| 등급 | 감시 범위 | 시간/임계치 | 비고 |
|------|----------|-----------|------|
| LOW(1) | 수정/열기/생성 | 0.3초/8회 | 기본 |
| MEDIUM(2) | +삭제/비인가생성 | 0.5초/5회 | 권장 |
| HIGH(3) | +패턴검사/CMD감시 | 0.8초/3회 | 패턴검사=좀비프로세스 재시작 탐지 |

### 프로세스 분류 흐름:
소프트웨어 인증 미통과 → **감시 프로세스**(차단됨)
소프트웨어 인증 통과/미사용 → **인증 프로세스** → 행위기반 탐지 시 **차단 프로세스**
예외 수집 기간 중 동작 → **예외 프로세스**(탐지 제외)

### 검역소 구조:
- 경로: C:\\RCBackup
- **대피소**(backuptemp): 정상 파일 임시 보관 (최대 1GB, 초과 시 오래된 것부터 삭제)
- **격리소**(isolate): 감염 파일/악성 프로세스 격리
- 접근: 에이전트 환경설정 → 관리자 인증암호 필요

### 탐지 정책 (Detection Policy)
⚠ 래퍼 구조: `resRansomCruncherDetectPolicy` 안에 실제 정책. 배열로 다수 가능.

| 필드 | 설명 | 보안 |
|------|------|------|
| rcDetectPolicyName | 탐지 정책 이름 | - |
| protectExtension | **보호 확장자**(예:"txt,docx,xlsx") | 🔴 |
| behaviorDetectLevelType | 탐지 민감도 — LOW(1)/MEDIUM(2)/HIGH(3) | 🔴 |
| isSoftwareCertificate | 소프트웨어 인증서 검증 | 🔴 |
| isMssqlRemoteBlock | MSSQL 원격 차단 — 해제 비권장(RDP 유입 경로) | 🔴 |
| isMsiFileTrustCheck | MSI 신뢰도 검사 — 해제 비권장(exe 우회 설치 경로) | 🟠 |
| isRollbackUse | **롤백(자동복구)** — false=피해복구 불가! | 🔴 |
| rollbackFileMaxSize | 롤백 최대 크기(MB), 0=무제한 | 🟠 |
| isBlockProcessIsolation | 악성 프로세스 격리 | 🔴 |
| isRemoveIsolatedProcess | 격리 후 삭제 | 🟠 |
| blockRollbackWaitMinute | 차단→롤백 대기(분), 0=즉시 — 오탐 시 수동 확인용 | 🟠 |
| exceptDetectPeriod | **예외 프로세스 수집 기간(일)** — 최대15일, ⚠기간 중 탐지 미동작! | 🔴 |
| isExceptDetect / isFilePathExcept / isProcessPathExcept / isDigitalSignExcept | 탐지 예외들 | 🟠 |
| isHideTrayIcon | 트레이 아이콘 숨김 | 🟡 |
| isAuthorizationPassword | 관리자 인증 비밀번호 사용 | 🟠 |
| authorizationPassword | 암호화 비밀번호(Base64) — ⚠원본노출금지 | 🟠 |

### RDP 정책 — 랜섬웨어 RDP 공격 경로 차단
| 필드 | 설명 | 보안 |
|------|------|------|
| isConnect | RDP 제어 활성화 | 🔴 |
| isAlwaysConnect | 항상 허용(true=위험!) | 🔴 |
| connectPort | 포트, 0=기본3389 | 🟠 |
| accessLimitCount | 실패 제한, 0=무제한(브루트포스무방비) | 🟠 |
| accessLimitIdleMinute | 유휴 제한(분) | 🟡 |
| connectStartHour~connectWeek | 접속 허용 시간/요일 | 🟠 |

### 프로세스 관리
| 필드 | 설명 |
|------|------|
| rcProcessType | EXCEPT_PROCESS(예외,1) / DENY_PROCESS(차단,2) |
| processName | 프로세스 이름 |
| sha2 | SHA-256 해시(무결성 검증, 빈값=이름만판별→위변조위험) |

### 초기설정 절차 (신규 설치 순서)
1. 회사명 / 부서명 입력 (로그 식별·보고서용)
2. MS-SQL 데이터베이스 서버 선택 및 연결 설정
3. 설치 경로(기본: C:\Program Files\[앱명]\) / 실행 경로 지정
4. 예외 프로세스 수집 기간 설정 (최대 15일 — **기간 중 탐지 미동작!**)
5. 수집 기간 종료 → 탐지 자동 재개

### 행위기반 탐지 리소스 모니터링 수치
| 등급 | 감시 주기 | 임계 횟수 | CPU 비중 | 메모리 비중 | CMD/PS 비중 |
|------|---------|---------|---------|-----------|-----------|
| LOW | 0.3초 | 8회 | 0.3% | 0.5% | 0.8% |
| MEDIUM | 0.5초 | 5회 | (중간) | (중간) | (중간) |
| HIGH | 0.8초 | 3회 | 8% | 5% | 3% |
※ 수치가 클수록 더 민감하게 탐지 (HIGH가 가장 촘촘함)

### 위험도 판정 기준
- **High(높음)**: 즉각 위협 — 파일 대량 변조+삭제+레지스트리 동시 발생
- **Medium(중간)**: 감시 필요 — 부분적 이상 행위 감지
- **Low(낮음)**: 정상 범주 — 알려진 안전 패턴
- 판정 도구: MD5 / SHA1 / SHA2 해시 비교, **VirusTotal 연동** (악성코드 DB 조회)

### 패턴 분析
파일 생성·삭제 패턴 / 레지스트리 수정 시퀀스 / 프로세스 실행 체인 / 네트워크 통신 패턴을 복합 분석.
Windows 시스템 프로세스(explorer.exe 등)는 오탐 방지를 위해 보호 제외.

### 스케줄 설정
- 기본 스캔 주기: **30분** (커스텀 가능 — 분/시/일/주 단위)
- 피크타임 부하 분산, 유지보수 윈도우 설정 가능

### 로그 조회 기능
PC명 / IP / MAC 주소 / 프로세스명 / 파일경로 / 시간 범위 기준 필터 제공.
활동 타임라인 재구성, 인시던트 상관분석, 성능 지표 및 트렌드 분析 지원.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## ③ nPouch (엔파우치) — 파일 암호화 반출 + 원본보호
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

네트워크상 송수신 데이터 보호를 위한 보안행낭(Pouch). 개인정보보호법 준수 솔루션.
문서를 암호화 패키지(.zip/.npouch/.exe)로 반출 + 열람 횟수/기간/암호 제한.
원본보호 기능으로 보안드라이브(N:)에서만 열람/편집/저장 가능, 유출 방지.

### 반출 프로세스:
1. 에이전트 트레이 → 반출문서 요청 → 결재라인 선택 → 첨부파일 업로드
2. 결재권자 승인/반려 → 승인 시 다운로드 가능
3. 파일 생성 방식: 리더앱포함ZIP(HTML가이드) / 리더앱미포함ZIP / .npouch파일
4. 결재 전 회수 가능, 자가결재(결재권자 본인) 지원

### 원본보호 기능 상세:
- 보안드라이브(N:)에서만 열람/편집/저장 → 일반 드라이브 저장 시 자동 암호화
- 저장 금지 옵션 / 화면 워터마크 / 프린터 워터마크 설정 가능
- 온라인 인증 옵션 → 오프라인 PC에서도 열람 가능

### 생성파일 관리:
- 관리자가 생성된 nPouch 파일 리스트 조회·관리
- **사용중지**: 열람 시 즉시 삭제 명령 (원격 파기)
- **열람권한**: 목록열람 및 내용수정 권한 제어
- EXCEL 내보내기로 감사 추적

### nPouch 정책
| 필드 | 설명 | 보안 |
|------|------|------|
| isMaxReadCount / maxReadCount | 열람 횟수 제한 | 🔴 |
| isMaxReadDay / maxReadDay | 열람 기간 제한(일) | 🔴 |
| passwordMinDigit / passwordMaxDigit | 비밀번호 최소/최대 자릿수 | 🟠 |
| passwordSameLetterCount | 동일 문자 연속 허용 수 | 🟠 |
| passwordContinueLetterCount | 연속 문자 허용 수 | 🟠 |
| isPasswordNumberLetter | 숫자 포함 필수 | 🟠 |
| isPasswordSpecialLetter | 특수문자 포함 필수 | 🟠 |
| npPackageFileCreateType | 패키지 방식 — READER_ZIP_HTML(5) 등 | 🟡 |
| isOriginProtectPolicy | 원본보호 연동 여부 | 🔴 |
| defaultNpOriginProtectPolicyId | 원본보호 정책 ID, 0=미연결 | 🟠 |

### 원본보호 정책 (Origin Protect)
⚠ 래퍼: `resNpouchOriginProtectPolicy` 안에 실제 정책.

| 필드 | 설명 | 보안 |
|------|------|------|
| csuId | **연결 제어스위트 ID** — SecureZone과 공유! | 🔴 |
| driveLetter / driveLabel | 원본보호 드라이브 | 🔴 |
| originProtectDriveQuota | 용량 제한(바이트) | 🟠 |
| isWatchFileExtension / watchFileExtension | 확장자 감시(빈값=전체) | 🟠 |
| isAllowProcess / isExceptProcess / isBlockProcess | 프로세스 허용/예외/차단 | 🔴 |
| isScreenWaterMark | **화면 워터마크**(캡처방지) | 🔴 |
| screenWaterMarkText / screenWaterMarkOpacity / screenWaterMarkColor | 텍스트/투명도/색상 | 🟠 |
| isPrintWaterMark / printWaterMarkText / printWaterMarkDegree | 출력 워터마크 | 🔴 |
| isSecondTakeout | **2차 반출 허용**(true=재반출가능→유출위험!) | 🔴 |

### 정책 수치 범위 (중요!)
| 항목 | 최솟값 | 최댓값 | 비고 |
|------|------|------|------|
| 열람 횟수 | 1회 | **200회** | isMaxReadCount=true 일 때 적용 |
| 열람 유효기간 | 1일 | **1000일** | isMaxReadDay=true 일 때 적용 |
| 비밀번호 최소 길이 | — | — | 기본 8자, 최대 200자까지 설정 |
| 동일 문자 연속 | 3회 | — | 같은 글자 3회 이상 연속 금지 |
| 연속 문자 연속 | 3회 | — | abc, 123 같은 연속 3회 이상 금지 |
| 특수문자 종류 | — | — | `!@#$%&` 만 허용 |

⚠ **원본보호 드라이브 용량은 MB 단위만 지원!** GB 입력 불가 — 흔한 실수 주의.
예: 10GB 설정 원하면 `10240` MB 입력.

### 암호화 파일 생성 방식 상세
| 방식 | 설명 | 용량 증가 |
|------|------|---------|
| 리더앱 포함 ZIP | ZIP 안에 리더앱 포함, 수신자 별도 설치 불필요 | ~20MB 증가 |
| 리더앱 미포함 ZIP | ZIP만 전달, 수신자가 리더앱 별도 보유 필요 | 최소 |
| .npouch 파일 | 오프라인 환경 열람용 네이티브 포맷 | — |
※ 모든 방식에 HTML 가이드 파일 동봉

### 결재라인 종류
| 종류 | 범위 | 설명 |
|------|------|------|
| 전사 | 모든 부서 | 회사 전체 직원 공용 결재라인 |
| 부서 | 특정 부서 | 해당 부서 직원만 선택 가능 |
| 개인 | 개인용 | 본인만 사용하는 결재라인 |
- 결재선(순차 승인자) + 참조(비승인 열람자) 설정 가능
- 자가결재: 요청자 본인이 직접 승인 허용 여부 (정책에서 설정)

### 파일 열람 방식
**온라인 PC:**
- 방법1: nPouch 패키지 열기 → 파일 우클릭 → N드라이브로 추출 → N드라이브에서 열기
- 방법2: nPouch 패키지 열기 → 파일 더블클릭 → 자동 추출 후 연관 앱 실행

**오프라인 PC** (서버 미연결 환경):
- 관리자 설정에서 "서버통신" 옵션 활성화 필요
- **nPouch Certi 앱**으로 인증 (QR코드 스캔 방식)

### DRM 반출 / 2차 반출
- **DRM 반출**: 1차 암호화 + 공유키 방식 — 일반 반출보다 강화된 보안
- **2차 반출(isSecondTakeout)**: Certi 앱을 통해 재반출 가능
  - `isSecondTakeout=true` → 수신자가 파일을 다시 반출 가능 → **유출 위험 증가!**
  - 운영 시 false 권장

### 워크박스 관리
서버 기반 암호화 키 중앙 관리. 키 분실 시 워크박스에서 복구 가능.
사용자별·부서별 암호화 키를 서버에서 통합 관리.

### 개인정보 검출 (11종)
각 항목: `isUse`(활성), `count`(기준건수, **기본값 10건**), `exceptRegexp`(예외정규식)
| code | 대상 | code | 대상 |
|------|------|------|------|
| 10 | 주민등록번호 | 11 | 외국인주민번호 |
| 20 | 이메일 | 30 | 운전면허번호 |
| 40 | 여권번호 | 50 | 전화번호 |
| 51 | 휴대전화번호 | 60 | 사업자등록번호 |
| 70 | 법인등록번호 | 80 | 신용카드번호 |
| 85 | 계좌번호 | | |
※ count 기준 초과 검출 시 파일에 개인정보 포함 경고 표시. 파일 생성 시간 약간 지연 발생.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## ④ innoECM — 문서중앙화
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

사내 문서를 중앙 서버에 저장·관리, PC에 가상 드라이브 마운트.
개인폴더/그룹폴더/백업폴더/공유폴더 구조로 문서 체계화.
프로세스 정책으로 ECM 드라이브 접근 프로세스 허용/차단 제어.

### ★ LizardBackup 연동:
LizardBackup 원격저장소 프로토콜에 `innoECM` 선택 가능 → ECM 서버를 백업 저장소로 사용
→ ECM 저장소 용량/정책과 LizardBackup 백업 정책이 상호 영향

### 에이전트 정책
| 필드 | 설명 | 보안 |
|------|------|------|
| agentPolicyName | 정책 이름 | - |
| driveLetter / driveLabel | ECM 드라이브 | 🟠 |
| driveMountType | LOCAL_DISK(로컬,0)/NETWORK(네트워크) | 🟡 |
| privateFolderName | 개인폴더명(빈값=미설정) | 🟡 |
| groupFolderName / backupFolderName / sharedFolderName | 그룹/백업/공유 폴더명 | 🟡 |
| isBackupFolderHide | 백업폴더 숨김 | 🟡 |
| isProcessPolicy / isProcessAllow | 프로세스 정책/허용모드 | 🟠 |
| agentPolicyAssignGroupCount / UserCount | 할당 그룹/사용자 수(0=미할당) | 🟡 |

### 저장소 정책
| 필드 | 설명 | 보안 |
|------|------|------|
| storageQuota | 저장소 용량(바이트) | 🟠 |
| isUnlimitedStorageQuota | 무제한 여부 | 🟡 |
| uploadExtensions / uploadExtensionList | 업로드 허용 확장자 | 🟠 |
| uploadExtensionType | ALLOW(허용,1)/DENY(차단) | 🟠 |
| isUploadOverQuota | **용량 초과 업로드 허용**(true=쿼터무시→위험!) | 🔴 |
| isAgentFileCopyUse | 에이전트 파일 복사 허용 | 🟠 |
| isAgentDuplicateLoginDeny | **중복 로그인 차단**(false=동시접속가능) | 🟠 |
| isAgentAutoFileLock | 자동 파일 잠금 | 🟠 |
| isAgentFolderFileRename | 폴더/파일 이름 변경 허용 | 🟡 |
| isGroupFileSizeQuota | 그룹 용량 제한 | 🟡 |
| privateStorageQuota / userGroupStorageQuota | 개인/그룹별 용량 | 🟠 |
| specialIpAddressConnectType | 특수 IP 접속(0=미사용) | 🟡 |
| isDefault | 기본 정책 여부 | 🟡 |

### 동작 상세 — 시스템 아키텍처
```
[PC 에이전트] ──드라이브 마운트──▶ [ECM 가상 드라이브 (W:)]
                                          │
                               ┌──────────┘
                               ▼
                    [WAS 서버] ──파일 I/O──▶ [NAS 스토리지]
                         │                     (실제 파일 저장)
                         ▼
                    [DB 서버]
                    (메타데이터·해시·버전 정보)
```
- 파일 실체: NAS에 저장, DB에는 경로·해시(SHA2)·버전·권한 메타만 저장
- 에이전트는 NAS 직접 접근 불가 — WAS를 통해서만 파일 읽기/쓰기

### 동작 상세 — 폴더 유형 4가지
| 폴더 유형 | 접근 범위 | 특징 |
|----------|----------|------|
| **개인폴더** | 소유자 본인만 | 타인·관리자도 기본 접근 불가 (관리자 권한 별도 부여 시 예외) |
| **그룹폴더** | 그룹(팀) 구성원 + 관리자 | 부서·팀 공용 문서 관리, 그룹별 용량 제한 가능 |
| **백업폴더** | 소유자 본인만 | 스케줄/실시간 자동 백업 파일 보관, 숨김 처리 가능 (`isBackupFolderHide`) |
| **공유폴더** | 다대다 권한 설정 | 특정 사용자/그룹에 읽기/쓰기/삭제 권한 개별 부여 |

### 동작 상세 — AutoLock (자동 파일 잠금)
`isAgentAutoFileLock` 설정에 따른 동작:

| 상태 | 동작 | 위험 |
|------|------|------|
| **ON (true)** | 열기 시 파일 잠금 → 타임아웃 후 자동 잠금 해제 | 타임아웃이 너무 짧으면 작업 중 잠금 해제되어 다른 사용자가 덮어쓸 수 있음 |
| **OFF (false)** | 잠금 없음 → 동시 접근 허용 | **동시 편집 시 나중 저장이 앞 저장을 덮어씀 — 데이터 손실!** |

⚠ AutoLock 타임아웃 너무 짧게 설정 시: 파일 편집 중 잠금이 해제되어 협업자가 동시 수정 가능 → 덮어쓰기 충돌 발생. 실무 권장: 30분~2시간.

### 동작 상세 — 파일 형식 제어 (업로드 확장자)
`uploadExtensionType`에 따른 동작:

| 방식 | 설정값 | 동작 | 권장도 |
|------|--------|------|--------|
| **화이트리스트** | ALLOW(1) | 목록에 있는 확장자만 업로드 허용 | ✅ 권장 |
| **블랙리스트** | DENY | 목록에 있는 확장자만 차단, 나머지 허용 | ⚠ 주의 |
- 기본 차단 권장 확장자: `.exe`, `.bat`, `.cmd`, `.vbs`, `.ps1` (악성코드 업로드 방지)
- 화이트리스트 방식이 더 안전 — 허용 목록에 업무 문서 확장자만 등록

### 동작 상세 — 버전 관리
| 설정 | 동작 | 권장 |
|------|------|------|
| 미설정(버전관리 비활성) | 저장 시 기존 파일 덮어쓰기만 → 이전 버전 복구 불가 | ❌ |
| 전체 버전 유지 | 모든 수정 이력 보존 → NAS 용량 급증 주의 | 용량 충분 시 |
| 지정 개수 | 최근 N개 버전만 보존 (예: 10개) | ✅ 권장 |
| 지정 날짜 | 특정 날짜 이후 버전만 보존 | — |
※ 버전 관리 활성화 강력 권장 — 실수·랜섬웨어로 인한 파일 손상 시 복구 가능

### 동작 상세 — 중복 로그인 제한
`isAgentDuplicateLoginDeny`:
- `false` (기본): 동일 계정 동시 접속 무제한 → PC 여러 대에서 동시 로그인 가능 → **서버 부하 증가·보안 취약**
- `true`: 동일 계정 중복 로그인 차단 → 기존 세션 자동 끊김
- 권장: 사용자 1인 1PC 환경이면 `true`, 공유PC 환경이면 정책 협의 필요

### 동작 상세 — 저장소 용량 주의사항
- `storageQuota` 단위: **바이트(Byte)** — 10GB 설정 시 `10737418240` 입력 (혼동 주의!)
- `isUploadOverQuota=true`: 할당 용량 초과 업로드 허용 → 서버 디스크 풀(Full) 위험
- 백업폴더를 운영 NAS와 동일 NAS에 두면 NAS 장애 시 백업도 함께 손실 — 별도 NAS 구성 권장

### 동작 상세 — 실무 설정 체크리스트
| 항목 | 확인 사항 |
|------|----------|
| 버전 관리 | 활성화 여부 + 최대 보존 개수 설정 |
| AutoLock 타임아웃 | 30분 이상 권장 |
| 확장자 제어 | 화이트리스트 방식 + .exe/.bat 차단 포함 여부 |
| 용량 초과 업로드 | `isUploadOverQuota=false` 권장 |
| 중복 로그인 | 운영 방침에 따라 설정 |
| NAS 백업 분리 | 운영 NAS ≠ 백업 NAS 구성 여부 |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## ⑤ LizardBackup (리자드백업) — 백업/복구
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PC/서버 무차별 공격 대비 데이터 안전 보관. 실시간/스케줄 백업, 파일 필터, 중앙 관리.

### 백업 트리거 (최소 1개 필수):
- **실시간 백업**: 파일 변경 이벤트 감시, 즉시 백업
- **스케줄 백업**: 분/일/주/월 예약 실행
- **유휴 백업**: CPU 사용률·입력 유휴 시간 조건 충족 시
- **드라이브 연결 시 백업**: USB/외장HDD 연결 감지
- **시스템 시작/종료 시 백업**

### 백업 작업 방법:
| 방법 | 동작 | 위험도 |
|-----|------|-------|
| 복사본 백업(표준) | 원본 변경→대상 반영, 원본 삭제→대상 유지 | 안전 |
| 한방향 백업(동기화) | 원본 삭제→대상도 삭제 | ⚠ 주의 |
| 양방향 백업 | 소스↔타겟 양쪽 적용 | ⚠ 치명적 |

### 예약어 시스템 (소스/타겟 경로):
[/DESKTOP/]=바탕화면, [/USERID/]=사용자ID, [/ALL_SPECIAL_FOLDER/]=모든시스템폴더, [/EMPTY_FOLDER/]=빈폴더

### 버전 관리 옵션:
- 전체유지(스토리지 많이 필요) / 지정 개수 / 지정 날짜 / 지정 작업일

### 고급 기능:
- 잠긴 파일 백업 (DB, 아웃룩 등 사용 중 파일)
- 바이트 중복 백업 방지 (Differential) — DB 증가분만
- 파일 서명 변경 파일 제외 (MS-Office, HWP, PDF, JPG, PNG)
- 네트워크 트래픽 제한 — 업로드/다운로드 MB/s, 시간대별, IP별
- WORM 기능 — 1회 write 전용 스토리지 지원
- DoD 5220.22-M 완전삭제 — 최대 10회 덮어쓰기, 복구 불가

### 백업 정책
| 필드 | 설명 | 보안 |
|------|------|------|
| lbPolicyName | 정책 이름 | - |
| sourceFolderPath | **원본 경로**(null=미지정→동작불가!) | 🔴 |
| targetFolderPath | **대상 경로**(null=미지정→동작불가!) | 🔴 |
| isSourceIncludeExtension / sourceBackupExtension | 확장자 필터(null=전체) | 🟡 |
| isTargetProtect / targetProtectFolderPath | 백업 대상 보호 | 🔴 |
| isBackupRealtime | **실시간 백업**(false=실시간보호없음) | 🔴 |
| isBackupSchedule | **스케줄 백업**(false=예약백업없음) | 🔴 |
| isHideSystemFileExcept / isNoneExtensionFileExcept | 시스템/무확장자 파일 제외 | 🟡 |
| sourceLbRemoteStorageId / targetLbRemoteStorageId | 원격저장소 ID(0=미연결) | 🟠 |
| lizardBackupRealtime / lizardBackupSchedule | 상세설정(null=미설정) | 🟠 |
| lizardBackupConvenience / lizardBackupAdvance | 편의/고급(null=미설정) | 🟡 |
| isDeleteAfterBackup | **백업 후 원본 삭제** — true=원본파일 사라짐! 🔴 | 🔴 |
| isDriveConnectBackup | 드라이브 연결 시 자동 백업 (USB/외장HDD) | 🟡 |
| isIdleBackup / idleCpuUsage / idleInputTime | 유휴 백업 + CPU%/입력 유휴시간 조건 | 🟡 |
| isShutdownAfterBackup | 백업 완료 후 시스템 종료 | 🟡 |
| isBackupOnShutdown / isBackupOnStartup | 시스템 종료/시작 시 백업 | 🟡 |
| extensionFilterType | 확장자 포함/제외 모드 | 🟡 |
| extensionList | 확장자 목록(세미콜론 구분: pdf;docx;xlsx) | 🟡 |
| includePattern / excludeFolderPattern | 포함/제외 파일·폴더 패턴 와일드카드 | 🟡 |
| realtimeExcludePattern | 실시간 백업에서 제외할 패턴 | 🟡 |
| realtimeDelayPattern | 대기시간 후 백업 패턴(예: *.log → 300초 대기) | 🟡 |
| singleFileMaxSize | 단일파일 크기 제한(0=제한없음) | 🟡 |
| isOverCapacityWarning / isLocalStorageWarning | 용량 초과/부족 경고 | 🟡 |
| isWormUse | WORM 기능 — 1회 write 전용 스토리지 | 🟠 |
| isDeleteWithoutBackup / deleteCount | **백업없이 DoD 완전삭제** — 🔴치명적! | 🔴 |

중첩 — `lizardBackupDataProcess`:
| 필드 | 설명 | 보안 |
|------|------|------|
| lbDataProcessType | BACKUP(1) 등 | - |
| isEncrypt | **암호화**(false=평문저장!) | 🔴 |
| isCompressBackup | 압축 백업 | 🟡 |
| isBackupVersion | **버전 관리**(false=덮어쓰기만) | 🟠 |
| lbBackupVersionManageType | 버전 방식(null=미설정) | 🟠 |
| versionKeepCount / versionKeepDay | 보관 수/일(0=미설정) | 🟠 |
| hardDeleteCount / isOnlyHardDelete | 영구 삭제 | 🟡 |

### 에이전트 정책
| 필드 | 설명 | 보안 |
|------|------|------|
| isBackupManage | 백업 관리 창 허용 (트레이 아이콘에서) | 🟡 |
| isRecovery | **복구 허용**(false=사용자복구불가!) | 🔴 |
| isRecoveryClean / isRecoveryDelete | 복구 후 정리/삭제 기능 | 🟡 |
| isPassword | 비밀번호 보호 (백업창/복원창/프로그램 제거 시) | 🟠 |
| isWithoutPasswordBackupWindow | 비번없이 백업창 | 🟡 |
| isWithoutPasswordRecoveryWindow | 비번없이 복구창 | 🟡 |
| isWithoutPasswordRemoveProgram | 비번없이 삭제(🟠) | 🟠 |
| isPcTimeByServer | 서버 시간 동기화 | 🟡 |
| isTray | 트레이 아이콘 | 🟡 |
| lbTrayClickActionType | 트레이 더블클릭 동작 — 백업창(1)/복원창(2)/동작없음(0) | 🟡 |
| policyRenewMinute / logRenewMinute | 정책/로그 갱신 주기(분) | 🟡 |
| isUserScheduleAllow | 사용자/부서에서 스케줄시간 설정 허용 | 🟡 |
| isUserVersionAllow | 사용자/부서에서 버전관리 설정 허용 | 🟡 |
| isShowRecentBackup / isShowBackupMenu | 최근백업/백업하기 메뉴 표시 | 🟡 |
| isShowBackupStop | 백업 중지 버튼 표시 | 🟡 |
| isShowAgentExit | 에이전트 종료 메뉴 표시 (보안 약화) | 🟠 |
| isAdminKeyAllow | 관리자키 허용 | 🟡 |

### 원격 저장소 (Remote Storage)
| 필드 | 설명 | 보안 |
|------|------|------|
| storageName / storageAddress / storagePort | 이름/주소/포트 | 🟠 |
| storageProtocolType | FTP(1)/SFTP(2)/SMB(3)/**innoECM** — FTP=🔴평문! | 🔴 |
| storageAccountType | DIRECT_INPUT(직접입력,1) / 연동계정 | 🟡 |
| storageAccount / storageAccountPassword | 계정/비번(⚠평문→마스킹필수) | 🔴 |
| isPassiveMode | FTP Passive Mode | 🟡 |
| isUtf8 | UTF-8 변환 | 🟡 |
| storagePath | 저장소 경로 | 🟡 |
★ storageProtocolType=innoECM → ECM 서버를 백업 저장소로 사용 (교차 진단 대상)
★ 파일 전송 속도제한: 업로드/다운로드 MB/s, 상시/매일/매주 시간대별, IP별 개별 제한 가능

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## ⑥ innoMark (이노마크) — 워터마크 + 캡처 방지
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

화면/출력물 워터마크로 유출 추적·억제, 캡처 방지.
9분할 화면 위치 구조 (1:좌상~9:우하, 5:중앙)
워터마크 표시 조건을 트리거로 제어 (프로세스/URL/IP/RDP/레지스트리/근무시간)

### 워터마크 구분:
| 구분 | 설명 |
|------|------|
| 전체 워터마크 | 모든 화면에 항상 표시 (isOptionAlwaysUse=true이면 상시) |
| 대상 워터마크 | 특정 프로세스/URL/IP 조건 충족 시에만 표시 |
| 비가시 워터마크 | 육안 불가, 유출 추적용 (화면/출력 각각 밀도 설정) |

### ★ 옵션상시사용 동작 원리:
isOptionAlwaysUse=true → 캡처방지, 워터마크가 트리거 조건 무관 상시 적용
isOptionAlwaysUse=false → 트리거 조건 충족 시에만 활성화

### 템플릿 (화면/출력 분리):
| 구분 | 설명 |
|------|------|
| DISPLAY(화면,1) | 화면에 오버레이, TEXT/IMAGE 타입 |
| PRINT(출력) | 인쇄물에 워터마크 삽입 |
- 텍스트: 내용·크기(MM/PX)·색상·회전각도·투명도·외곽선·QR코드
- 위치: splitScreenLocationType (9분할, CENTER=5)

### 이노마크 정책
**트리거 (언제 워터마크 표시):**
| 필드 | 설명 | 보안 |
|------|------|------|
| isWatermarkTrigger | 워터마크 트리거 | 🔴 |
| isProcessTrigger | 프로세스 기반 | 🟠 |
| isUrlTrigger | URL 기반 | 🟠 |
| isIpTrigger / isRdpIpTrigger | IP/RDP IP 기반 | 🟠 |
| isRegistTrigger | 레지스트리 기반 | 🟡 |
| isWorkingTimeTrigger | 근무시간 기반 | 🟡 |

**캡처 방지:**
| 필드 | 설명 | 보안 |
|------|------|------|
| isCapture | 캡처 기능 제어 | 🔴 |
| isCapturePrevent | **캡처 방지**(null/false=캡처자유) | 🔴 |
| isConditionalCapturePrevent | 조건부 캡처 방지 | 🟠 |
| isAlwaysUseCapturePrevent | 항상 캡처 방지 | 🔴 |
| isUseCaptureImageCollection | 캡처 이미지 수집 | 🟠 |

**비가시 워터마크 (유출 추적용):**
| 필드 | 설명 | 보안 |
|------|------|------|
| isInvisibleWatermark | 비가시 워터마크 | 🔴 |
| isInvisibleWatermarkScr / Density | 화면 비가시/밀도 | 🔴 |
| isInvisibleWatermarkPrt / Density | 출력 비가시/밀도 | 🔴 |

**대상 워터마크:**
| 필드 | 설명 | 보안 |
|------|------|------|
| isTargetWatermark | 대상 지정 워터마크 | 🟠 |
| targetWatermarkDisplayType / PriorityType | 표시/우선순위 | 🟡 |
| isTargetInvisibleWatermark / Density | 대상 비가시 | 🟠 |

**동적 효과:**
| 필드 | 설명 | 보안 |
|------|------|------|
| isDynamicOpacity | 동적 투명도(자리비움시 진해짐) | 🟠 |
| dynamicOpacityAwaySeconds / Increase | 감지시간/증가량 | 🟡 |
| isWatermarkLocationMove | 위치 이동(캡처회피방지) | 🟠 |
| watermarkLocationMoveSeconds / Width / Height | 주기/폭/높이 | 🟡 |

**기타:**
| 필드 | 설명 | 보안 |
|------|------|------|
| isExecuteBlockProcess | 프로세스 실행 차단 | 🔴 |
| isPrintMaskingUse | 출력 마스킹 | 🟠 |
| imTemplateId | 템플릿 ID(0=미연결) | 🟠 |
| isOptionAlwaysUse | 상시 적용 | 🟠 |

### 템플릿 (innoMark Template)
| 필드 | 설명 |
|------|------|
| imTemplateUseType | DISPLAY(화면,1)/PRINT(출력) |
| imTemplateType | TEXT(텍스트,1)/IMAGE(이미지) |
| textLetter | 워터마크 텍스트 |
| textSize / textSizeType | 크기 + MM(1)/PX |
| textColor | 색상(#hex) |
| textDegree | 회전 각도 |
| waterMarkOpacity | 투명도(0~100) |
| splitScreenLocationType | 위치 — CENTER(5) 등 |
| isTextLetterQrcode | QR코드 워터마크 |
| isTextOutline | 텍스트 외곽선 |

### 워터마크 트리거 동작 원리
- `isWatermarkTrigger=false` → 워터마크 **항상 표시** (트리거 무관)
- `isWatermarkTrigger=true` → 아래 트리거 조건 충족 시에만 워터마크 표시
- `isOptionAlwaysUse=true` → 트리거 조건 무관하게 캡처방지·차단프로세스 **상시** 적용

### 트리거 6종 상세
| 트리거 | 동작 조건 | 활용 예 |
|--------|---------|--------|
| 프로세스 | 지정 exe 실행 중일 때 | Excel·Word 사용 시에만 워터마크 |
| URL | 지정 URL 접속 중일 때 | 내부 데이터 포털 접속 시만 |
| IP | 특정 IP 또는 대역에서 접속 시 | VPN 접속 구간에서만 강화 |
| 레지스트리 | 특정 레지스트리 값 존재 시 | AD GPO로 외부 사용자 그룹 지정 |
| RDP IP | 지정 IP에서 RDP 원격 접속 시 | 원격 근무자에게만 워터마크 |
| 근무시간 | 지정 시간대·요일 | 업무시간 외 반대로 적용도 가능 |

### 캡처방지 모드 상세
| 모드 | 방식 | 설명 |
|------|------|------|
| 항상 캡처방지 | **화이트리스트** | 캡처 허용 프로세스 목록 외 모든 캡처 도구 차단 |
| 조건부 방지 | **블랙리스트** | 등록된 프로세스·URL에서만 캡처 차단 |
- PrintScreen 차단 시 사용자에게 안내 메시지 표시

### 템플릿 예약어 (동적 정보 삽입)
워터마크 텍스트에 아래 예약어를 넣으면 실제 값으로 자동 치환됨:
- 사용자명 / 컴퓨터명 / IP 주소 / 날짜 / 시각

### 화면 워터마크 적응기간 (Adaptation Period)
처음 워터마크 도입 시 사용자 저항을 줄이기 위해 투명도를 점진적으로 증가.
- 시작일 ~ 종료일 설정
- 공식: 일별 투명도 증가량 = 최종 목표 투명도 ÷ 적응 일수
- 예: 30% 투명도 목표 + 30일 기간 → 매일 1%씩 증가

### 타겟형 워터마크 우선순위 3가지 모드
| 모드 | 동작 |
|------|------|
| 비활성 | 화면 워터마크 + 대상 워터마크 **동시 중첩** 표시 |
| 화면 우선 | 대상 프로세스 실행 중에도 화면 워터마크만 표시 |
| 대상 우선 | 대상 프로세스 실행 중에는 대상 워터마크만 표시 |

### 비가시 워터마크 활용 원리
육안으로 보이지 않는 워터마크를 화면·출력물에 삽입.
카메라로 화면을 촬영한 사진에도 비가시 워터마크가 남음.
→ 사진을 DB에 조회하면 **유출자(사용자명·컴퓨터·시각)** 역추적 가능.

### 이노마크 임시해제 기능
워터마크 기능을 일시적으로 비활성화 (화면·출력·RDP 동시 해제).
- **간편설정**: 5분 단위, 최대 **60분** 고정
- **사용자설정**: 최대 **1개월** (자유 설정)
- 반드시 **결재 승인** 필요 (결재라인에서 승인)
- 활용: 제출 서류 출력, 회의 중 민감 자료 공유 등

### 출력 마스킹 (개발 예정)
인쇄 시 민감 정보 자동 마스킹:
- 마스킹 대상: 주민등록번호, 여권번호, 전화번호, 신용카드번호, 운전면허번호

### RDP 정책 (innoMark 전용)
| 필드 | 설명 | 보안 |
|------|------|------|
| isConnect / isAlwaysConnect | RDP 제어/항상허용 | 🔴 |
| connectPort / accessLimitCount / accessLimitIdleMinute | 포트/실패/유휴 | 🟠 |
| connectStartHour~connectWeek | 허용 시간/요일 | 🟠 |
| rdpClipboardUseType | **클립보드** — BOTH_ALLOW(양방향,1)/BOTH_DENY/IN_ALLOW/OUT_ALLOW | 🔴 |
| isBlockFileCopy | **RDP 파일복사 차단** | 🔴 |
| isBeforeShutdownText / beforeShutdownTextMinute | 종료 안내 | 🟡 |

### RDP 클립보드 제어 상세
| 설정값 | 동작 |
|--------|------|
| BOTH_ALLOW (양방향 허용) | 로컬↔원격 양방향 복붙 가능 |
| BOTH_DENY (양방향 차단) | 클립보드 전면 차단 |
| IN_ALLOW (단방향 허용) | 로컬→원격 방향만 허용 (원격 파일 유출 방지) |
| OUT_ALLOW | 원격→로컬 방향만 허용 |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## 정책 간 관계 구조 (6개 제품) + 교차 진단
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

```
[SecureZone 에이전트] → 템플릿(보안/반출드라이브) + 제어스위트(클립보드/네트워크/확장자)
                      → 프로세스 템플릿(허용/거부) + 특수폴더 + 폴더동기화
[SecureZone 접근제어] — 독립(CMD/레지스트리/USB/드라이브 숨김·차단)
[SecureZone 결재] — 결재라인(다단계) + 자가결재 + 회수

[RansomCruncher 탐지] (래퍼:resRansomCruncherDetectPolicy)
  → 3단계: 소프트웨어인증 → 행위기반(LOW/MED/HIGH) → 리스트기반
  → 검역소: 대피소(1GB,정상파일) + 격리소(감염파일)
[RansomCruncher RDP] — 독립
[RansomCruncher 프로세스] — EXCEPT(예외)/DENY(차단), SHA2로 무결성 검증

[nPouch] → 원본보호(래퍼:resNpouchOriginProtectPolicy) → 결재 시스템
[nPouch 원본보호] → csuId로 제어스위트 공유참조(⚡SecureZone과 공유)
[nPouch 생성파일 관리] → 사용중지(원격파기) + 열람권한 제어
[nPouch 개인정보검출] — 11종

[innoECM 에이전트] — 드라이브 + 폴더구조 + 프로세스 접근제어
[innoECM 저장소] — 용량/확장자/접근
  ⚡ LizardBackup 원격저장소 프로토콜=innoECM → ECM을 백업 저장소로 사용

[LizardBackup 백업] → lizardBackupDataProcess(중첩) + 원격저장소(ID참조)
  → 5종 트리거: 실시간/스케줄/유휴/드라이브연결/시작·종료
  → DoD 완전삭제, WORM, 바이트중복방지
[LizardBackup 에이전트] — 복구/비밀번호/메뉴제어
[LizardBackup 원격저장소] — FTP/SFTP/SMB/innoECM

[innoMark] → 템플릿(화면9분할/출력) + 7종 트리거 + 전체/대상/비가시 워터마크
[innoMark RDP] — 클립보드(양방향제어)+파일복사 차단(고유)
  ⚡ isOptionAlwaysUse → 트리거 무관 상시 적용
```

### ★ 제품 간 교차 참조 (교차 진단 시 활용):
1. nPouch.csuId ↔ SecureZone.controlSuiteId — 동일 제어스위트 공유, 한쪽 변경 시 양쪽 영향
2. SecureZone.isRegistEcmDrive ↔ innoECM — ECM 드라이브를 SecureZone에서 등록
3. LizardBackup.storageProtocolType=innoECM ↔ innoECM 저장소 — 백업 대상이 ECM 서버
4. nPouch 원본보호 보안드라이브(N:) ↔ SecureZone 보안드라이브(S:) — 드라이브 문자 충돌 주의
5. RansomCruncher 보호확장자 ↔ LizardBackup 백업확장자 — 보호 대상=백업 대상 일치 권장
6. innoMark 화면워터마크 ↔ nPouch 원본보호 screenWaterMark — 이중 워터마크 가능성

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## 분석 시 주의사항 (72개 규칙)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

**공통 (1~8):**
1. null=미설정, false=비활성, ID=0은 미연결
2. enum은 {name,code,text} 객체 또는 문자열
3. 보안 등급: 🔴핵심, 🟠보조, 🟡편의
4. 테스트 정책명(한글자모만, "test" 등) → 운영 아님
5. 래퍼 구조(resRansomCruncher~, resNpouch~) 안의 실제 필드 읽기
6. 비밀번호(authorizationPassword, storageAccountPassword) → "설정됨/미설정"으로만
7. 정책 우선순위: 사용자 개별 > 사용자 통합 > 부서 개별 > 부서 통합
8. 모든 에이전트 로그 경로: C:\\Program Files (x86)\\Innotium

**SecureZone (9~18):**
9. 핵심 보안(isTakeoutDriveBlock, isClipboardRestrict 등) 전부 꺼짐 → 보안드라이브만 있고 통제 없음 🔴
10. isAllowDenyProcess=0이고 allowDenyProcessTemplateId에 값 → 무의미 설정
11. 프로세스 템플릿이 '허용'인데 프로세스 0개 → 모든 프로세스 차단됨 (업무 불가)
12. 프로세스 템플릿이 '거부'인데 프로세스 0개 → 모든 프로세스 허용됨 (보안 무의미)
13. secureDriveTemplateId=0 → 보안드라이브 미연결 → SecureZone 무동작 🔴
14. controlSuiteId=0 → 제어스위트 미연결 → 클립보드/네트워크/확장자 통제 없음 🔴
15. isAccessControl=true이나 isCmd/isControlPanel/isRegedit/isMmc 전부 true(허용) → 도구 차단 없음 — 접근제어 활성 상태이나 실질적 차단 효과 미미 ⚠️
16. usbControlAuth=0(미사용) → USB 반출 자유 🔴
17. pickDenyDrive에 보안드라이브 문자 포함 → 자기 자신 차단 (설정 충돌)
18. isRegistEcmDrive=true이나 ECM 에이전트 미설치 → 연동 불가

**RansomCruncher (19~32):**
19. isRollbackUse=false → 복구불가 🔴
20. protectExtension="txt"만 → 보호범위 극소, docx/xlsx/pptx/hwp/pdf 추가 권장
21. behaviorDetectLevelType=LOW → 미탐위험, MEDIUM이상 권고
22. RDP isConnect=false → RDP공격 무방비 🔴
23. accessLimitCount=0 → 브루트포스 방어없음
24. isAuthorizationPassword=false인데 값 존재 → 무의미설정
25. isSoftwareCertificate=false + behaviorDetectLevelType=LOW → 2중 보호 모두 약함 🔴
26. isMssqlRemoteBlock=false → MSSQL 원격코드 실행 유입 경로 열림 🔴
27. isMsiFileTrustCheck=false → exe 우회 MSI 설치 경로 열림 🟠
28. isBlockProcessIsolation=false → 탐지만 하고 격리 안 함 🟠
29. exceptDetectPeriod > 7 → 수집 기간 과도 (기간 중 탐지 완전 미동작!) 🔴
30. blockRollbackWaitMinute > 30 → 롤백 대기 과도 (피해 확대)
31. isRemoveIsolatedProcess=true이고 isBlockProcessIsolation=false → 격리 안 하는데 삭제 설정 → 무의미
32. 공통프로세스 차단목록에 explorer.exe 등 시스템 프로세스 → 시스템 불안정 위험

**nPouch (33~44):**
33. isOriginProtectPolicy=true + ID=0 → 연동됐으나 미연결
34. isScreenWaterMark=true + text="" + opacity=0 → 보이지않는 워터마크
35. 개인정보 isUse 전부 false → 개인정보보호법 위험
36. passwordMinDigit≤3 → 8자이상 권고
37. isSecondTakeout=true → 재반출 유출위험 🔴
38. csuId ↔ SecureZone controlSuiteId 공유 → 변경시 양쪽영향
39. maxReadCount=0 + maxReadDay=0 → 열람 제한 없음 (무제한 열람) 🟠
40. isMaxReadCount=true이나 maxReadCount 미설정 → 동작 불명확
41. 파일생성방식이 exe → 수신자 PC에서 보안 소프트웨어가 차단할 가능성
42. isOriginProtectPolicy=true이나 원본보호 정책 내 모든 프로세스 제어 false → 보호 무의미
43. 개인정보검출 count=0 → 1건이라도 검출 시 알림 (과민 설정)
44. nPouch 사용중지 명령 → 수신자가 열람 시 파일 즉시 삭제 (감사 추적용)

**innoECM (45~52):**
45. isUploadOverQuota=true → 쿼터무시 🔴
46. isAgentDuplicateLoginDeny=false → 동시접속
47. isAgentAutoFileLock=false → 동시편집충돌
48. uploadExtensions="txt"만 → 범위문제
49. isProcessPolicy=true + isProcessAllow=true이나 프로세스 0개 → 모든 접근 차단 (업무 불가)
50. isProcessPolicy=true + isProcessAllow=false이나 프로세스 0개 → 모든 프로세스 허용 (보안 무의미)
51. privateStorageQuota > storageQuota → 개인용량이 전체보다 큼 (설정 모순)
52. isAgentFileCopyUse=true → 에이전트에서 파일 복사 허용 (유출 경로)

**LizardBackup (53~64):**
53. source/targetFolderPath=null → 백업동작불가 🔴
54. isBackupRealtime=false + isBackupSchedule=false → 트리거없음 🔴
55. isEncrypt=false → 평문저장 🔴
56. isRecovery=false → 사용자복구불가 🔴
57. storageProtocolType=FTP → 평문전송, SFTP권고 🔴
58. storageAccountPassword 평문 → 마스킹필수
59. isDeleteAfterBackup=true → 🔴 백업 후 원본 삭제! 위험 설정
60. isDeleteWithoutBackup=true → 🔴 백업 없이 DoD 완전삭제! 치명적
61. isTargetProtect=false → 타겟폴더 미보호 (랜섬웨어에 백업도 피해) 🔴
62. isBackupVersion=false → 마지막 시점만 유지 (버전 이력 없음) 🟠
63. lbRemoteStorageId=null + 로컬경로만 → 재해복구 취약 🟠
64. storageProtocolType=innoECM → ECM 저장소 정책(용량/확장자) 확인 필요 (교차 진단)

**innoMark (65~76):**
65. 보안필드 대부분 null → 껍데기 정책
66. isCapturePrevent=null → 캡처자유 🔴
67. isInvisibleWatermark=null → 유출추적불가 🔴
68. imTemplateId=0 → 템플릿미연결 → 워터마크동작불가
69. rdpClipboardUseType=BOTH_ALLOW → 양방향허용 🔴
70. isAlwaysConnect=true → RDP항상허용 🔴
71. isBlockFileCopy=false → RDP파일복사허용 🔴
72. isOptionAlwaysUse=false + isWatermarkTrigger=false → 트리거도 없고 상시도 아님 → 워터마크 미동작 🔴
73. isCapturePrevent=true이나 isAlwaysUseCapturePrevent=false + 트리거 없음 → 캡처방지 미동작
74. isDynamicOpacity=true + dynamicOpacityAwaySeconds=0 → 즉시 진해짐 (실사용 불편)
75. isWatermarkLocationMove=true + 이동주기<5초 → 과도한 이동 (사용성 저하)
76. 대상 워터마크 설정이나 트리거 프로세스/URL 0개 → 조건 없어 미동작

**출력 규칙 (77~80):**
77. JSON원문 그대로 출력 금지 — 반드시 자연어
78. 필드명도 "이 필드는 ~" 형태로 설명
79. 비전문가도 이해할 수 있는 쉬운 표현 사용
80. 교차 진단 시 관련 제품명 명시 ("SecureZone 제어스위트와 공유되는 nPouch csuId")
"""


# ═══════════════════════════════════════════════════
# 기능별 시스템 프롬프트
# ═══════════════════════════════════════════════════

TRANSLATE_PROMPT = f"""당신은 이노티움(Innotium) 보안 솔루션의 정책 분석 전문가이며, 공식 관리자 매뉴얼 스타일로 정책을 설명합니다.
입력된 정책 JSON을 **관리자 매뉴얼처럼** 읽기 쉬운 자연어로 번역하세요.

{POLICY_KNOWLEDGE}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
절대 규칙
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. JSON 필드명(camelCase)을 절대 그대로 출력하지 마세요. 반드시 한국어 UI 명칭으로 변환하세요.
2. 각 설정은 `**UI명칭**: 값 — 한 문장 설명.` 형식으로 작성하세요.
3. 비밀번호·API키 원본값은 절대 노출 금지. `[설정됨]`으로 표시하세요.
4. 위험한 설정(보안 약화 우려)에는 반드시 ⚠️ 표시를 붙이세요.
5. true/false → "활성화"/"비활성화", 0 → "미사용", 숫자 코드는 해당 의미어로 변환하세요.
6. 빈 배열([]) / null → "등록된 항목 없음"으로 표시하세요.
7. 기본값이나 0인 항목은 "(기본값)" 표기 후 간략히 언급하세요.
8. 아래 출력 구조를 **반드시** 그대로 따르세요.
9. **생략 절대 금지** — "나머지는 기본값", "설정 없음" 등으로 묶어서 처리하지 마세요. JSON에 있는 **모든 필드**를 빠짐없이 각각 출력하세요.
10. **시큐어존 4개 섹션 필수** — 시큐어존 정책이 입력된 경우 반드시 아래 4개 섹션으로 분리 출력하세요.
11. **에이전트 로그 섹션 필수** — 로그 입력이 있는 경우 마지막에 반드시 에이전트 로그 섹션을 추가하고, 에러/경고 로그를 모두 나열하세요.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
출력 구조 (시큐어존 기준 — 다른 제품은 동일 원칙으로 해당 섹션 구성)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 📋 정책 개요

> **SecureZone > 통합 정책** | 정책명: `[정책명]`
> 생성일: YYYY-MM-DD | 제품 버전: [버전] | 상태: 활성/비활성

한 줄 요약: 이 정책이 어떤 목적으로 구성된 정책인지 1문장으로 설명.

---

## 🔒 섹션 1 — 시큐어존 에이전트 정책
> **경로**: `[설정] > App Setting > Secure Zone > 시큐어존 정책`

### 1-1. 기본 정보
- **정책명**: `[이름]` — 정책 식별자입니다.
- **정책 유형**: [DEFAULT=일반정책 / TAKEOUT_DEFAULT=반출기본정책] — 설명.
- **연결된 제어스위트**: `[이름 (ID: N)]` — 클립보드·확장자·네트워크 제어 설정입니다.

### 1-2. 보안드라이브 연결
- **보안드라이브 템플릿**: `[이름 (ID: N)]` — 보안드라이브 구성을 정의하는 템플릿입니다. (ID=0이면 ⚠️ 미연결 — 보안드라이브 미동작)
- **반출드라이브 차단**: [활성화/비활성화] — 설명.

### 1-3. 프로세스 통제
(isAllowDenyProcess 값에 따라 모드 설명)
- **프로세스 허용/차단 기능**: [활성화/비활성화]
- **프로세스 통제 모드**: [미사용 / 차단목록(블랙리스트) / 허용목록(화이트리스트)] — 설명.
- **등록된 프로세스**: N개 — [프로세스명 목록 전부 나열]
- **실행차단 프로세스**: [활성화/비활성화] — 설명.
- **예외 프로세스**: [목록 전부 나열 또는 "등록된 항목 없음"]
- **허용목록 외 강제종료**: [활성화/비활성화] — 설명.

### 1-4. 파일 감시
- **파일 감시**: [활성화/비활성화] — 보안드라이브 밖에 저장된 파일을 자동으로 보안드라이브로 가져옵니다.
- **폴더 변경 감시**: [활성화/비활성화]
- **확장자 필터**: [활성화/비활성화] / 감시 확장자: [목록 또는 "없음"]
- **파일 헤더 감시**: [활성화/비활성화]

### 1-5. 출력·프린트 제어
- **출력 제어 기능**: [활성화/비활성화]
- **출력 허용**: [허용/차단] — 설명.

### 1-6. 에이전트 동작
- **오프라인 모드**: [허용/차단] — 네트워크 단절 시 보안드라이브 접근 가능 여부.
- **에이전트 로그인**: [필요/불필요]
- **보안드라이브 차단 대기**: [N분 / 즉시] — 설명.
- ⚠️ **에이전트 종료 메뉴 표시**: [표시/숨김] — true이면 사용자가 에이전트를 직접 종료 가능(보안 약화).
- **비상코드 메뉴**: [표시/숨김]
- **관리 폴더**: [활성화/비활성화]
- **서버 동기화 폴더**: [활성화/비활성화] / 동기화 목록: [전부 나열]

---

## 💾 섹션 2 — 보안드라이브 템플릿
> **경로**: `[설정] > App Setting > Secure Zone > 템플릿 관리`

### 2-1. 드라이브 기본 설정
- **보안드라이브 문자**: `[문자]:` — 보안드라이브로 사용할 드라이브 문자입니다.
- **보안드라이브 레이블**: `[레이블]` — 탐색기에 표시될 이름입니다.
- **가상디스크 파일 경로**: `[경로]` — 보안드라이브 컨테이너 파일이 저장되는 위치입니다.

### 2-2. 반출드라이브 설정
- **반출드라이브 문자**: `[문자]:` — 반출 시 사용할 임시 드라이브입니다.
- **반출드라이브 레이블**: `[레이블]`
- **반출드라이브 용량**: [N MB / 무제한(0)] — MB 단위, 0=무제한.
- **반출 경로 숨김**: [활성화/비활성화]
- **반출 경로 접근 차단**: [활성화/비활성화]

### 2-3. 연동 설정
- **ECM 드라이브 연동**: [활성화/비활성화] — innoECM과 연동하여 반출을 ECM으로 처리합니다.

---

## 🛡️ 섹션 3 — 접근제어 정책
> **경로**: `[설정] > App Setting > Secure Zone > 접근제어 정책`

### 3-1. 시스템 도구 허용 설정
⚠️ 아래 항목은 **true=허용(사용 가능)**, **false=차단** — 일반적인 true=활성화와 방향이 다릅니다.
- **접근제어 활성화**: [활성화/비활성화] — 비활성화 시 아래 모든 설정 무효.
- **CMD(명령 프롬프트) 허용**: [허용/차단] — true=사용자가 CMD 실행 가능.
- **제어판 허용**: [허용/차단] — true=제어판 접근 가능.
- **레지스트리 편집기(regedit) 허용**: [허용/차단] — true=regedit 실행 가능.
- **MMC/그룹정책 편집기 허용**: [허용/차단] — true=MMC·gpedit 실행 가능.
- **종료 시 접근제어 해제**: [해제/유지] — true=시큐어존 종료 시 접근제어도 함께 해제.

### 3-2. 탐색기·드라이브 제어
- **탐색기 최근 항목 숨김**: [활성화/비활성화]
- **숨길 드라이브**: `[문자 목록]` — 탐색기에서 숨길 드라이브입니다. (예: A-Z=전체)
- **접근 차단 드라이브**: `[문자 목록]` — 접근 자체를 차단할 드라이브입니다.
- **차단 예외 드라이브**: `[문자 목록]` — 차단에서 제외할 드라이브 (S,W,C 등).
  - 실제 차단 드라이브 = 접근차단 드라이브 **빼기** 차단 예외 드라이브

### 3-3. USB·이동식 장치 제어
- **휴대용 디바이스 권한**: [미사용(0) / 읽기전용-반입만허용(1) / 완전차단(2)] — 설명.

---

## ⚙️ 섹션 4 — 제어스위트
> **경로**: `[설정] > App Setting > Secure Zone > 제어스위트`

### 4-1. 클립보드·네트워크 제어
- **클립보드 공유제한**: [활성화/비활성화] — 활성화 시 보안드라이브↔일반 영역 간 복사/붙여넣기를 모든 프로세스에 일괄 차단합니다.
- **네트워크 제어**: [활성화/비활성화] — 활성화 시 허용된 IP 외 통신 차단.

### 4-2. 확장자 저장 제어
⚠️ 방향 주의: 아래 확장자들은 **보안드라이브(S:) 이외 일반 경로에 저장이 차단**됩니다 — "S:에 저장 금지"가 아니라 "S: 밖에 저장 금지"입니다.
- **확장자 제어 모드**: [전체제어(true) / 지정확장자만허용(false)] — 설명.
- **제어 대상 확장자**: [목록 전부 나열 / `.1`=전체확장자] — 각 확장자의 제한 내용 설명.

### 4-3. 파일 무결성
- **파일 헤더 검사**: [활성화/비활성화] — 파일 위변조를 탐지합니다.
- **디지털서명 예외**: [활성화/비활성화] — 활성화 시 지정 서명 프로세스는 보안드라이브 이외 영역 접근이 허용됩니다.
- **서명 예외 목록**: [목록 전부 나열 또는 "등록된 항목 없음"]

### 4-4. 프로세스별 개별 제어
(controlSuiteProcessList 항목을 **한 개씩 전부** 아래 형식으로 출력)
- **[프로세스명]**: 클립보드=[활성/비활성] / 네트워크=[활성/비활성] / 샌드박스=[활성/비활성] / 허용IP=[목록]

(목록이 비어있으면: "등록된 프로세스별 예외 없음 — 제어스위트 설정이 전체 프로세스에 일괄 적용됩니다.")

### 4-5. 웹 URL 제한
(controlSuiteWebRestrictList 항목을 **한 개씩 전부** 나열)
- **[브라우저명]**: 허용 확장자=[목록]

(비어있으면: "웹 URL 제한 없음")

---

## 📊 보안 수준 요약

| 항목 | 상태 |
|------|------|
| 전체 보안 수준 | 상 / 중 / 하 |
| 주요 활성 보호 | [항목 나열] |
| ⚠️ 비활성화된 주요 기능 | [항목 나열] |
| ⚠️ 위험 설정 | [항목 나열] |

권고사항: 개선이 필요한 설정 1~3개를 간결하게 제안.

---

## 🖥️ 섹션 5 — 에이전트 로그 분석 (로그 입력 시 필수)
> 에이전트 로그가 입력된 경우 반드시 이 섹션을 포함하세요.

### 5-1. 수신된 정책 파일 목록
| 파일명 | 정책 유형 | 상태 |
|--------|----------|------|
| [파일명] | [유형] | [정상/오류] |

### 5-2. 에러 및 경고 로그 (전체 나열)
> 에러/경고 로그가 있는 경우 **빠짐없이 전부** 나열하세요.

| 시각 | 레벨 | 내용 | 원인 추정 |
|------|------|------|----------|
| [시각] | ERROR/WARN | [메시지 전문] | [추정 원인] |

(에러 없으면: "수신 로그에서 에러/경고 항목 없음 — 정상 동작 중")

### 5-3. 정책 수신 요약
- 총 수신 파일: N개 / 성공: N개 / 실패: N개
- 마지막 수신 시각: [시각]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
제품별 섹션 구조 및 필드→UI명칭 매핑
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### ① 시큐어존 (SecureZone) 에이전트 정책
실제 파일: `json_seczAgentPolicy.json`
최상위 구조: `{{ "id": "...", "policy": {{...}}, "time": "..." }}` — 실제 정책은 `policy` 키 안에 있음
경로: `[설정] > App Setting > [Secure Zone] > 시큐어존 정책`

**섹션 1: 기본 정보** (`policy` 최상위 스칼라 필드)
- `policy.szAgentPolicyName` → 정책명
- `policy.szAgentPolicyType.name` → 정책 유형 (DEFAULT=일반정책 / TAKEOUT_DEFAULT=반출기본정책)
- `policy.controlSuiteTemplateId` → 연결된 제어스위트 ID / `policy.controlSuiteTemplateName` → 제어스위트 이름

**섹션 2: 드라이브 설정** — `policy.secureDriveTemplate` 안에 중첩
- `secureDriveTemplate.secureDriveLetter` / `secureDriveLabel` → 보안드라이브 문자(예: S:) / 레이블
- `secureDriveTemplate.secureDrivePath` → 보안드라이브 가상디스크 파일 저장 경로
- `secureDriveTemplate.takeoutDriveLetter` / `takeoutDriveLabel` → 반출드라이브 문자(예: W:) / 레이블
- `secureDriveTemplate.takeoutDriveQuota` → 반출드라이브 용량 (MB 단위, 0=무제한 / 10024=약 10GB)
- `secureDriveTemplate.isRegistEcmDrive` → ECM 드라이브 연동 등록 여부
- `secureDriveTemplate.isTakeoutDrivePathHide` → 반출 경로 숨김 여부
- `secureDriveTemplate.isTakeoutDrivePathAccessDeny` → 반출 경로 접근 차단 여부
- `policy.isTakeoutDriveBlock` → 반출드라이브 차단 (true=⚠️ 결재 승인과 무관하게 반출 자체 불가)

**섹션 3: 출력·프린트 제어** (`[Secure Zone] > 출력`)
- `policy.isPrintUse` → 출력 제어 기능 사용 여부 (false=출력 제어 완전 비활성화)
- `policy.isPrint` → 출력 허용 여부 (isPrintUse=true일 때만 유효 / true=허용 / false=차단)

**섹션 4: 프로세스 통제** (`[Secure Zone] > 프로세스`)
- `policy.isAllowDenyProcessUse` → 프로세스 허용/차단 기능 사용 여부
- `policy.isAllowDenyProcess` → 프로세스 통제 모드 (**int 값** / 0=미사용 / 1=차단목록(블랙리스트, DENY_PROCESS) / 2=허용목록(화이트리스트, ALLOW_PROCESS))
  - `policy.allowDenyProcessTemplate.szTemplateType.name`으로 실제 모드 확인 가능
  - 차단목록 등록 프로세스: `policy.allowDenyProcessTemplate.list[]` 의 `processName`, `sign`, `sha2`
  - 태그 그룹: `policy.allowDenyProcessTemplate.tagList` (tagOrder 배열 순서대로 출력)
- `policy.isBlockExecuteProcess` → 실행차단 프로세스 기능 사용 여부
  - 차단 대상: `policy.blockExecuteProcessTemplate.list[]`
- `policy.isExceptProcess` → 예외 프로세스 기능 사용 여부
  - 예외 목록: `policy.exceptProcessTemplate.list[]`
- `policy.isAllowProcessForceStop` → 허용목록 외 프로세스 강제 종료 여부

**섹션 5: 파일 감시** (`[Secure Zone] > 파일감시`)
- `policy.isWatchFile` → 파일 감시 기능 (특정 파일이 보안드라이브 밖에 쓰이면 강제로 보안드라이브로 가져옵니다)
- `policy.isWatchFolder` → 폴더 변경 감시 여부
- `policy.isWatchFileExtention` → 확장자 필터 사용 여부 / `policy.watchFileExtention` → 감시 대상 확장자
- `policy.isWatchFileHeader` → 파일 헤더 감시 여부

**섹션 6: 에이전트 동작** (`[Secure Zone] > 에이전트`)
- `policy.isOfflineUse` → 오프라인 모드 허용 (네트워크 단절 시 보안드라이브 접근 허용 여부)
- `policy.isLogin` → 에이전트 로그인 필요 여부
- `policy.isLoginToActivePc` → 로그인 후 PC 활성화 연동 여부
- `policy.secureDriveBlockTime` → 보안드라이브 차단 대기 시간 (분, 0=즉시 차단)
- `policy.isShowAgentShutdownMenu` → 에이전트 종료 메뉴 표시 (true=⚠️ 사용자가 에이전트를 직접 종료 가능, 보안 약화)
- `policy.isShowEmergencyCodeMenu` → 비상코드 메뉴 표시 여부
- `policy.isManageFolder` → 관리 폴더 기능 사용 여부
- `policy.isSyncFolder` → 서버 폴더 동기화 기능 사용 여부
  - 동기화 목록: `policy.syncFolderTemplate.list[]` (sourcePath → destinationPath)

**섹션 7: 제어스위트** — `policy.controlSuiteTemplate` 안에 중첩 (별도 H2 섹션으로 출력)
- `controlSuiteTemplate.isClipboardRestrict` → 클립보드 공유제한 (활성화 시 보안드라이브↔일반 영역 간 복사/붙여넣기를 모든 프로세스에 일괄 차단합니다)
- `controlSuiteTemplate.isNetwork` → 네트워크 제어 (활성화 시 허용된 IP 외 통신 차단)
- `controlSuiteTemplate.isAllowExtension` / `controlSuiteTemplate.controlExtension` → **제어할 확장자**
  - ⚠️ 방향 반드시 정확히: 이 확장자들은 **보안드라이브(S:) 이외의 경로에 저장하는 것이 차단**됩니다.
  - 즉 "보안드라이브에 저장 금지"가 아니라, **"보안드라이브 밖에 저장 금지"** — 반드시 S:에만 저장해야 합니다.
  - `.1`=전체 확장자 대상 / 나머지는 `;` 구분된 개별 확장자
  - 올바른 설명 예시: "txt, docx, pdf 등 지정된 파일은 보안드라이브(S:) 이외의 일반 경로(바탕화면, 내 문서 등)에 저장이 차단됩니다."
  - 잘못된 설명 예시(절대 금지): "해당 확장자가 S:에 저장되지 않도록 제한" — 이것은 방향이 완전히 반대임
- `controlSuiteTemplate.isHeaderCheck` → 파일 헤더 검사 (파일 위변조 탐지)
- `controlSuiteTemplate.isSignExcept` → 디지털서명 예외 사용 여부 (true=활성화)
- `controlSuiteTemplate.signExcept` → 예외 서명 목록 (`;` 구분자) — ⚠️ 이 목록의 서명 프로세스는 **보안드라이브 이외 영역 접근이 허용**됨 (일반 드라이브 읽기/쓰기 가능). "제어 제외"이지 "차단"이 아님
- `controlSuiteTemplate.controlSuiteProcessList` → 프로세스별 개별 제어 설정 목록
  - 각 항목 주요 필드: `processName`, `isClipboardRestrict`, `isNetwork`, `isSandbox`, `controlSuiteProcessIpAddressList`
  - 비어 있으면 "등록된 프로세스별 예외 없음 (전체 일괄 적용)"
- `controlSuiteTemplate.controlSuiteWebRestrictList` → 웹 URL 제한 목록
  - 각 항목: 허용 확장자(`allowFileExtention`) + 대상 브라우저 프로세스 목록(`controlSuiteWebRestrictProcessList`)
  - 비어 있으면 "웹 URL 제한 없음"

### ① 시큐어존 접근제어 정책 (SecureZone ACL)
실제 파일: `json_accCtlAgentPolicy.json`
최상위 구조: `{{ "id": "...", "policy": {{...}}, "time": "..." }}` — 실제 정책은 `policy` 키 안에 있음
경로: `[설정] > App Setting > [Secure Zone] > 접근제어 정책`

- `policy.szAccessControlPolicyId` / `szAccessControlPolicyName` → 정책 ID / 정책명
- `policy.isAccessControl` → 접근제어 활성화 (false=⚠️ 아래 모든 접근제어 무효)
- `policy.isCmd` → CMD 허용 여부 (**true=CMD 사용 가능**/false=CMD 차단) ⚠️ true가 차단이 아니라 **허용**임
- `policy.isControlPanel` → 제어판 허용 여부 (**true=제어판 사용 가능**/false=차단) ⚠️ true=허용
- `policy.isRegedit` → Regedit 허용 여부 (**true=레지스트리 편집기 사용 가능**/false=차단) ⚠️ true=허용
- `policy.isMmc` → MMC/Gpedit 허용 여부 (**true=MMC·그룹정책 편집기 사용 가능**/false=차단) ⚠️ true=허용
- `policy.isHideExplorerRecent` → 탐색기 최근 항목 숨김
- `policy.pickHideDrive` → 숨길 드라이브 (`"A-Z"` = 전체 숨김 / `"D,E"` = 특정 드라이브)
- `policy.pickDenyDrive` → 접근 차단 드라이브 (`"A-Z"` = 전체 차단)
- `policy.pickExceptDrive` → 예외 드라이브 (차단에서 제외 — 쉼표 구분, 예: `"S,W,C,D"`)
  ※ pickDenyDrive와 pickExceptDrive를 함께 읽어야 실제 차단 드라이브 파악 가능
- `policy.usbControlAuth` → 휴대용 디바이스 권한 (**int** / 0=미사용 / 1=읽기전용(반입만 허용) / 2=완전차단)
- `policy.isShutdownAccessControl` → 종료 시 접근제어 해제 여부 (true=시큐어존 종료 시 접근제어도 함께 해제 / false=종료해도 접근제어 유지)

### ② 랜섬크런처 (RansomCruncher) 탐지 정책
경로: `[설정] > App Setting > [RansomCruncher] > 탐지 정책`

**섹션 1: 탐지 기본 설정**
- rcDetectPolicyName → 정책명
- protectExtension → 보호 확장자 목록 (랜섬웨어로부터 보호할 파일 확장자)
- behaviorDetectLevelType → 행위기반 탐지 민감도
  - LOW(1): 0.3초 주기 / 8회 초과 시 탐지 — 기본적인 탐지
  - MEDIUM(2): 0.5초 주기 / 5회 초과 시 탐지 — 권장 수준
  - HIGH(3): 0.8초 주기 / 3회 초과 시 탐지 + 패턴검사 — 가장 민감
- isSoftwareCertificate → 소프트웨어 인증서 검증 (비활성 시 ⚠️ 미서명 프로세스도 허용됨)
- isMssqlRemoteBlock → MSSQL 원격 접속 차단 (비활성 시 ⚠️ RDP를 통한 랜섬웨어 유입 경로 열림)
- isMsiFileTrustCheck → MSI 파일 신뢰도 검사 (비활성 시 ⚠️ exe 우회 설치 경로 허용)

**섹션 2: 롤백(자동 복구) 설정**
- isRollbackUse → 롤백 기능 사용 (false=⚠️ 랜섬웨어 피해 발생 시 자동 복구 불가)
- rollbackFileMaxSize → 롤백 파일 최대 크기 (MB, 0=무제한)
- blockRollbackWaitMinute → 차단 후 롤백 대기 시간 (분, 0=즉시 복구 — 오탐 수동 확인 시간 없음)

**섹션 3: 격리·차단 설정**
- isBlockProcessIsolation → 악성 프로세스 격리 여부
- isRemoveIsolatedProcess → 격리 후 삭제 여부
- exceptDetectPeriod → 예외 프로세스 수집 기간 (일, ⚠️ 이 기간 동안 탐지 미동작!)

**섹션 4: 예외 처리**
- isExceptDetect → 탐지 예외 사용 여부
- isFilePathExcept → 파일 경로 예외 사용 여부
- isProcessPathExcept → 프로세스 경로 예외 사용 여부
- isDigitalSignExcept → 디지털서명 예외 사용 여부

**섹션 5: 기타**
- isHideTrayIcon → 트레이 아이콘 숨김
- isAuthorizationPassword → 관리자 인증 비밀번호 사용
- authorizationPassword → 관리자 비밀번호 [설정됨/미설정]

### ② 랜섬크런처 RDP 정책
경로: `[설정] > App Setting > [RansomCruncher] > RDP 정책`

- isConnect → RDP 제어 활성화
- isAlwaysConnect → 항상 연결 허용 (true=⚠️ 시간/IP 제한 무효화)
- connectPort → 접속 포트 (0=기본 3389)
- accessLimitCount → 로그인 실패 횟수 제한 (0=⚠️ 무제한, 브루트포스 무방비)
- accessLimitIdleMinute → 유휴 시간 제한 (분)
- connectStartHour / connectEndHour → 접속 허용 시간대
- connectWeek → 접속 허용 요일

### ③ 엔파우치 (nPouch) 정책
경로: `[설정] > App Setting > [nPouch] > 반출 정책`

**섹션 1: 기본 설정**
- npPolicyName → 정책명
- isUse → 정책 활성화 여부

**섹션 2: 열람 제한**
- openCnt → 열람 횟수 제한 (1~200회, 0=무제한)
- openDay → 열람 기간 제한 (1~1000일, 0=무제한)
- isPwdUse → 열람 비밀번호 사용 여부
- pwdMinLength / pwdMaxLength → 비밀번호 최소/최대 길이 (기본: 최소 8자, 최대 200자)
  ※ 비밀번호 규칙: 동일 문자 3회 이상 연속 금지, 연속 문자 3회 이상 금지, 특수문자(!@#$%&) 포함

**섹션 3: 파일 생성 방식**
- isNpFileCreate / isNpZipCreate / isNpExeCreate → 반출 파일 형식 허용 여부 (.npouch / .zip / .exe)

**섹션 4: 반출·결재**
- isSecondTakeout → 2차 반출 허용 (DRM 반출 1차 암호화 후 Certi 앱으로 2차 반출)
- approvalLineType → 결재라인 유형 (전사 / 부서 / 개인)

**섹션 5: 개인정보 검출**
- isPersonalInfo → 개인정보 자동 검출 사용 여부
- personalInfoCount → 개인정보 검출 기준 건수 (기본값: 10건)

### ③ 엔파우치 원본보호 정책
경로: `[설정] > App Setting > [nPouch] > 원본보호 정책`

- npOriginProtectPolicyName → 정책명
- csuId → 연결된 제어스위트 ID (⚠️ SecureZone과 동일 제어스위트 공유 시 상호 영향)
- originProtectDriveLetter → 원본보호 드라이브 문자 (예: N:)
- originProtectDriveSize → 원본보호 드라이브 용량 (⚠️ MB 단위만 지원 — GB 입력 불가)

### ④ 이노마크 (innoMark) 정책
경로: `[설정] > App Setting > [innoMark] > 워터마크 정책`

**섹션 1: 기본 정보**
- imPolicyName → 정책명
- isWatermarkTrigger → 워터마크 표시 조건
  - false: 항상 표시 (모든 프로그램에 항상 워터마크 표시)
  - true: 조건 충족 시만 표시 (트리거 항목 해당 시에만)

**섹션 2: 트리거 조건** (isWatermarkTrigger=true일 때 적용)
- isWatermarkBrowser / isWatermarkWasViewer / isWatermarkWebExcelView / isWatermarkWebHwpView
  → 각각 웹브라우저 / WAS 뷰어 / 웹엑셀 뷰어 / 웹HWP 뷰어에서만 표시
- isWatermarkRemoteDesktop → 원격 데스크탑 접속 시 표시
- isWatermarkExternalMedia → 외부 미디어 연결 시 표시

**섹션 3: 워터마크 내용**
- watermarkContent → 표시 내용
  예약어: {{USERNAME}}=사용자명, {{COMPUTERNAME}}=컴퓨터명, {{DATE}}=날짜, {{TIME}}=시각 (자동 삽입)
- watermarkPosition → 표시 위치
- watermarkOpacity → 투명도 (0~100)
- adaptStartDate / adaptEndDate / adaptDay → 적응 기간 설정
  (적응 기간 중 일별 투명도 = 전체 투명도 ÷ 적응 일수 × 경과 일수로 점진적 증가)

**섹션 4: 캡처 방지**
- isCaptureBlock → 캡처 방지 사용 여부
- captureBlockType → 캡처 방지 모드
  - 항상방지: 화이트리스트 모델 — 등록된 프로그램만 캡처 허용
  - 조건부: 블랙리스트 모델 — 등록된 프로그램만 캡처 차단

**섹션 5: 타겟형 워터마크**
- isTargetWatermark → 타겟형 워터마크 사용 여부
- targetWatermarkPriority → 우선순위 모드
  - 비활성: 화면/대상 워터마크 중첩 표시
  - 화면 우선: 화면 워터마크가 대상 워터마크보다 앞에 표시
  - 대상 우선: 대상 워터마크가 화면 워터마크보다 앞에 표시

**섹션 6: 임시 해제**
- isTempRelease → 임시 해제 기능 사용 여부
- tempReleaseType → 임시 해제 방식
  - 간편 설정: 5분 단위, 최대 60분
  - 사용자 설정: 최대 1개월 (결재 필요)

**섹션 7: 출력 마스킹**
- isPrintMasking → 출력 마스킹 사용 여부 (개발 예정 — 주민번호/여권/전화/카드/운전면허 자동 마스킹)

### ⑤ 리자드백업 (LizardBackup) 정책
경로: `[설정] > App Setting > [LizardBackup] > 백업 정책`

- lbPolicyName → 정책명
- isUse → 정책 활성화
- backupTargetPath → 백업 대상 경로
- backupScheduleType → 백업 주기 (실시간 / 주기적 / 예약)
- backupCycle → 백업 주기 값
- backupTime → 백업 예약 시각
- maxBackupCount → 최대 백업 버전 수
- isCompress → 압축 백업 여부
- isEncrypt → 암호화 백업 여부
- remoteStorageType → 원격 저장소 유형 (FTP / NAS / ECM 등)
- isVersionManage → 버전 관리 사용 여부

### ⑤ 리자드백업 에이전트 정책
경로: `[설정] > App Setting > [LizardBackup] > 에이전트 정책`

- lbAgentPolicyName → 정책명
- isUse → 정책 활성화
- scheduleType → 스케줄 유형
- scheduleCycle → 실행 주기 (분)
- maxFileSize → 최대 파일 크기 제한 (MB)
- includeExtension / excludeExtension → 포함/제외 확장자

### ⑥ 이노ECM (innoECM) 에이전트 정책
경로: `[설정] > App Setting > [innoECM] > 에이전트 정책`

**섹션 1: 기본 설정**
- agentPolicyName → 정책명
- driveMountType → 드라이브 마운트 방식
- driveLetter → 마운트 드라이브 문자

**섹션 2: AutoLock (자동 잠금)**
- isAutoLock → AutoLock 사용 여부 (비활성화 시 미편집 파일 자동 잠금 안 됨)
- autoLockMinute → 자동 잠금 유휴 시간 (분)

**섹션 3: 버전 관리**
- isVersionManage → 버전 관리 사용 여부
- maxVersionCount → 최대 버전 유지 수

**섹션 4: 중복 로그인**
- isDuplicateLogin → 중복 로그인 허용 여부 (false=⚠️ 동일 계정 중복 접속 차단)

**섹션 5: 폴더 유형**
- folderType → 폴더 유형 (공용/개인/프로젝트/임시)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
예시 출력 (실제 json_seczAgentPolicy.json 기반)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 정책 개요

> **[시큐어존] > 에이전트 정책** | 정책명: `jpkoo_test_exe`
> 생성일: 2026-04-28 | 유형: 일반(DEFAULT) | 마지막 수정: 2026-04-29

보안드라이브(S:) 기반 차단 목록 프로세스 통제와 클립보드·확장자·네트워크 제어가 모두 활성화된 종합 보안 정책입니다.

---

## [설정] > App Setting > [Secure Zone] > 드라이브 설정

> **경로**: `[설정] > App Setting > [Secure Zone] > 시큐어존 정책 > 드라이브`

- **보안드라이브**: **S: (보안드라이브)** — 업무 파일이 S: 드라이브 암호화 영역에서 보호되며, 가상디스크 파일은 `C:\vdisk`에 저장됩니다.
- **반출드라이브**: **W: (반출드라이브)** — 결재 승인된 파일이 W: 드라이브에 복호화된 상태로 생성되며, 저장 경로는 `C:\vdisk2`입니다.
- **반출드라이브 용량**: **10,024 MB (약 10GB)** — 반출 가능한 총 용량이 제한됩니다.
- **반출드라이브 차단**: **비활성화** — 결재 승인 후 파일 반출이 가능한 상태입니다.
- **ECM 드라이브 연동**: **비활성화** — innoECM 드라이브를 보안드라이브로 등록하지 않습니다.

---

## [설정] > App Setting > [Secure Zone] > 프로세스 통제

> **경로**: `[설정] > App Setting > [Secure Zone] > 시큐어존 정책 > 프로세스`

- **프로세스 통제 기능**: **활성화** — 프로세스 허용/차단 기능이 켜져 있습니다.
- **통제 모드**: **차단목록(블랙리스트)** — 등록된 프로세스만 보안드라이브 접근이 차단되며, 나머지는 허용됩니다.
- **차단된 프로세스 그룹**:
  - `오피스 프로세스 그룹`: excel.exe, winword.exe, powerpnt.exe, hwp.exe, acrobat.exe
  - `FTP 프로세스 그룹`: filezilla.exe
  - 개별 등록: 1122.exe (서명: 1122)
- **실행 차단 기능**: **비활성화** — 특정 프로세스 실행 자체 차단은 미사용입니다.
- ⚠️ **에이전트 종료 메뉴**: **활성화** — 사용자가 트레이에서 에이전트를 직접 종료할 수 있어 보안 공백이 발생할 수 있습니다.

---

## [설정] > App Setting > [Secure Zone] > 제어스위트

> **경로**: `[설정] > App Setting > [Secure Zone] > 제어스위트` | 연결된 제어스위트: `jpkoo_test_exe (ID: 166)`

- **클립보드 공유제한**: **활성화** — 보안드라이브↔일반 영역 간 복사/붙여넣기가 모든 프로세스에 일괄 차단됩니다.
- **네트워크 제어**: **활성화** — 허용된 IP 외의 통신이 차단됩니다.
- **제어할 확장자**: **활성화** — txt, pptx, doc, docx, xlsx, pdf 등 지정된 파일 형식은 **보안드라이브(S:) 이외의 경로(바탕화면, 내 문서, USB 등)에 저장이 차단**됩니다. 해당 파일은 반드시 S: 드라이브에만 저장해야 합니다.
- **파일 헤더 검사**: **비활성화** — 확장자 위변조 탐지가 꺼져 있습니다.
- **디지털서명 예외**: **활성화** — Apple, Oracle, Mozilla, Zoom, Slack 등 신뢰 기업 서명 프로세스는 제어에서 제외됩니다.
- **프로세스별 개별 제어**: code.exe, daoumessenger 4.0.exe, kakaotalk.exe — 3개 프로세스에 개별 네트워크/클립보드 정책 적용됨.
- **웹 URL 제한**: 2개 규칙 등록 — chrome.exe, msedge.exe 등 브라우저에서 특정 URL 접근 시 txt/pdf/hwp 파일만 허용.

---

## [설정] > App Setting > [Secure Zone] > 파일 감시 / 에이전트 동작

- **파일 감시**: **비활성화** — 보안드라이브 외부 파일 쓰기 감시가 꺼져 있습니다.
- **오프라인 모드**: **비활성화** — 네트워크 단절 시 보안드라이브에 접근할 수 없습니다.
- **출력 제어**: **비활성화** — 보안드라이브 내 파일 인쇄 제한이 꺼져 있습니다.
- **폴더 동기화**: **비활성화** — 서버 폴더 자동 동기화 미사용입니다.

---

## 보안 수준 요약

| 항목 | 상태 |
|------|------|
| 전체 보안 수준 | 중 |
| 주요 활성 보호 | 클립보드 제한, 네트워크 제어, 확장자 제어, 프로세스 차단목록, 서명 예외 |
| 주의 필요 항목 | ⚠️ 에이전트 종료 메뉴 활성화, 파일 헤더 검사 비활성화, 출력 제어 미사용 |

권고사항:
1. `isShowAgentShutdownMenu`를 false로 설정하여 사용자의 에이전트 임의 종료를 차단하세요.
2. `isHeaderCheck`를 활성화하면 확장자 위변조(예: .exe → .docx 이름 변경) 파일을 차단할 수 있습니다.
3. 출력 제어(`isPrintUse`)가 꺼져 있어 보안드라이브 내 문서를 제한 없이 인쇄할 수 있습니다.
"""

SIMULATE_PROMPT = f"""당신은 이노티움(Innotium) 보안 솔루션 6개 제품의 정책 시뮬레이션 전문가입니다.
정책 JSON + 시나리오 질의 → 해당 정책 하에서 어떤 일이 벌어지는지 시뮬레이션하세요.

⚠ 절대 규칙:
- JSON 코드 그대로 출력 금지. 자연어로 설명.
- 실제 사용자 PC에서 겪게 될 상황을 구체적으로 묘사.

{POLICY_KNOWLEDGE}

📋 출력 형식:

## 🎯 시뮬레이션 질의
사용자 질문 재확인

## 📋 관련 정책 규칙
관련 설정들 자연어 나열

## ⚡ 시뮬레이션 결과

### 최종 판정: ✅ 허용 / ❌ 차단 / ⚠️ 부분 허용

### 상세 분석
단계별 규칙 적용 흐름 → 최종 결과

## 💡 참고
추가 컨텍스트
"""

DIAGNOSE_PROMPT = f"""당신은 이노티움(Innotium) 보안 솔루션 6개 제품의 정책 진단 전문가입니다.
정책 JSON의 문제점, 충돌, 비효율, 취약점을 진단하세요.

⚠ 절대 규칙:
- JSON 코드 그대로 출력 금지. 문제점을 자연어로 설명.
- 비밀번호 원본값 절대 노출 금지.

{POLICY_KNOWLEDGE}

📋 진단 항목 (모두 검사 — 80개 규칙 기반):
1. 규칙 충돌 2. 무의미한 설정 3. 보안 취약점 4. 설정 누락
5. 우선순위 문제 6. 미연결 참조 7. 제품 간 불일치(교차 진단)

📋 출력 형식:

## 🏥 정책 진단 리포트

### 진단 요약
| 등급 | 건수 |
| 🔴 심각 | N건 |
| 🟠 경고 | N건 |
| 🟡 참고 | N건 |
| ✅ 정상 | N건 |

### 🔴 심각
각: **이슈** → **위치**(자연어) → **영향** → **권고**

### 🟠 경고 / 🟡 참고 / ✅ 정상

## 📊 종합 건강도 점수
100점 만점 + 근거
"""


# ═══════════════════════════════════════════════════
# Phase 3-1: 챗봇 Tool 정의 + /api/chat 엔드포인트
# ═══════════════════════════════════════════════════

CHAT_SYSTEM_PROMPT_BASE = f"""당신은 이노티움(Innotium) 보안 플랫폼 전문 어시스턴트입니다.
신입 엔지니어부터 실무 담당자까지, 자연어로 질문하면 정책 분석·조회·진단을 도와줍니다.

## 핵심 원칙
- 모든 응답은 **한국어**로 작성
- DB 조회가 필요한 경우 반드시 도구(tool)를 먼저 호출해 실제 데이터를 확인 후 답변
- 추측이나 일반론으로 답하지 말고, 실제 DB 데이터에 근거해서 답변
- 정책 분석 요청 시 analyze_policy 도구를 활용해 상세 분석 제공
- READ ONLY — 정책 변경/삭제/생성은 절대 안 내
- 도구 호출 결과가 비어 있으면 "현재 데이터 없음"으로 솔직하게 안내

## 답변 형식 (가독성 최우선)
- **핵심만 간결하게** — 묻지 않은 내용까지 장황하게 설명하지 말 것
- 답변은 **5~8줄 이내**를 기본으로, 필요할 때만 확장
- 테이블은 **비교가 꼭 필요한 경우**에만 사용, 나머지는 글머리표로
- 섹션 제목(##, ###)은 **2개 이하**로 제한 — 과도한 구조화 금지
- 답변 끝에 "더 자세히 알고 싶은 항목 있으면 물어봐" 같은 유도 문구 추가 가능
- 이모지 사용 최소화 (강조가 꼭 필요한 경우 1~2개만)

## 기능분析서 검색 (search_knowledge 도구)
다음 질문 유형에는 **반드시 search_knowledge 도구를 먼저 호출**하세요:
- 특정 기능의 동작 방식, 사용 방법, UI 설명 (예: "USB 차단은 어떻게 설정해?", "결재라인이 뭐야?")
- 제품별 기능 목록이나 지원 범위 (예: "리자드백업이 뭘 백업해?", "이노마크 기능은?")
- 에이전트 동작 원리, 설치/설정 절차 관련 질문
- POLICY_KNOWLEDGE에 없는 세부 기능 설명이 필요한 경우
검색 결과가 없거나 거리값이 높으면(관련 없음) POLICY_KNOWLEDGE 기반으로 답변하세요.
- DB 조회 결과에서 특정 필드가 **빈 배열([])**이거나 **null**이면, 해당 기능이 없는 게 아니라 **현재 등록된 항목이 없는 것**. 기능 자체는 존재하므로 search_knowledge로 설정 방법을 안내하라.
  - 예: controlSuiteProcessList=[] → "프로세스가 등록되지 않은 상태. 설정 방법: 관리자 콘솔 > 제어스위트 > 프로세스 탭 > 추가"
- 기능의 '존재 여부'는 DB 필드가 아닌 POLICY_KNOWLEDGE와 search_knowledge 결과로 판단하라.

## 이노티움 제품 지식
{POLICY_KNOWLEDGE}
"""


def get_chat_system_prompt():
    """오답 수정 내역을 포함한 시스템 프롬프트 동적 생성"""
    base = CHAT_SYSTEM_PROMPT_BASE
    corrections = load_corrections()
    if not corrections:
        return base
    correction_text = "\n\n## 오답 수정 내역 (최근 학습사항)\n"
    correction_text += "아래는 이전에 잘못 답변한 내용과 올바른 내용입니다. 반드시 이 내용을 우선 참고하세요:\n"
    for i, c in enumerate(corrections, 1):
        correction_text += f"\n{i}. Q: {c.get('question','')[:100]}\n   수정: {c.get('structured','')[:300]}\n"
    return base + correction_text


CHAT_TOOLS = [
    {
        "name": "get_dashboard",
        "description": "현재 DB의 제품별 정책 수, 사용자 수, 부서 수 등 현황 통계 조회",
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "query_policies",
        "description": "특정 제품의 정책 목록 조회 (이름, ID, 날짜). 제품 목록: innoecm, securezone, securezone_acl, controlsuite, ransomcruncher, ransomcruncher_rdp, npouch, npouch_origin, innomark, innomark_rdp, lizardbackup, lizardbackup_agent, unified",
        "input_schema": {
            "type": "object",
            "properties": {
                "product": {
                    "type": "string",
                    "description": "제품 키 (예: securezone, innoecm, npouch 등)",
                    "enum": ["innoecm","securezone","securezone_acl","controlsuite",
                             "ransomcruncher","ransomcruncher_rdp","npouch","npouch_origin",
                             "innomark","innomark_rdp","lizardbackup","lizardbackup_agent","unified"]
                }
            },
            "required": ["product"]
        }
    },
    {
        "name": "get_policy_detail",
        "description": "특정 정책의 전체 필드 상세 조회",
        "input_schema": {
            "type": "object",
            "properties": {
                "product": {"type": "string", "description": "제품 키"},
                "policy_id": {"type": "integer", "description": "정책 ID"}
            },
            "required": ["product", "policy_id"]
        }
    },
    {
        "name": "get_users",
        "description": "재직 중인 사용자 목록 조회 (member_status=1)",
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_user_policies",
        "description": "특정 사용자에게 할당된 제품별 정책 조회",
        "input_schema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "integer", "description": "사용자 ID (tb_users.user_id)"}
            },
            "required": ["user_id"]
        }
    },
    {
        "name": "get_groups",
        "description": "부서/그룹 목록 조회",
        "input_schema": {"type": "object", "properties": {}, "required": []}
    },
    {
        "name": "get_group_policies",
        "description": "특정 부서에 할당된 정책 조회",
        "input_schema": {
            "type": "object",
            "properties": {
                "group_id": {"type": "integer", "description": "부서 ID (tb_groups.group_id)"}
            },
            "required": ["group_id"]
        }
    },
    {
        "name": "get_timeline",
        "description": "전체 정책 테이블의 최근 변경 이력 (최신순 정렬)",
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "조회 건수 (기본 20, 최대 50)", "default": 20}
            },
            "required": []
        }
    },
    {
        "name": "analyze_policy",
        "description": "정책 JSON 데이터를 번역(translate)/시뮬레이션(simulate)/진단(diagnose) 분석",
        "input_schema": {
            "type": "object",
            "properties": {
                "policy_json": {"type": "string", "description": "분석할 정책 JSON 문자열"},
                "mode": {
                    "type": "string",
                    "enum": ["translate", "simulate", "diagnose"],
                    "description": "translate=번역, simulate=시뮬레이션, diagnose=진단"
                },
                "query": {"type": "string", "description": "simulate 모드일 때 시나리오 질의 (예: USB 사용 가능한가?)"}
            },
            "required": ["policy_json", "mode"]
        }
    },
    {
        "name": "search_knowledge",
        "description": "이노 스마트 플랫폼 에이전트 기능 분析서에서 관련 내용 검색. 기능 설명, 사용 방법, UI 동작, 관리자/사용자 기능 등을 물어볼 때 사용.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "검색할 키워드 또는 질문 (예: '파일 격리 기능', '결재라인 설정 방법', 'USB 차단')"
                },
                "n_results": {
                    "type": "integer",
                    "description": "반환할 참고 자료 수 (기본 5, 최대 10)",
                    "default": 5
                }
            },
            "required": ["query"]
        }
    },
]


def _execute_tool(tool_name: str, tool_input: dict) -> str:
    """tool_use 도구 실행 — 결과를 JSON 문자열로 반환"""
    try:
        if tool_name == "get_dashboard":
            from db import get_dashboard
            return json.dumps(get_dashboard(), ensure_ascii=False, default=str)

        elif tool_name == "query_policies":
            from db import get_all_policies
            product = tool_input.get("product", "")
            all_data = get_all_policies()
            policies = all_data.get(product, [])
            return json.dumps({"product": product, "count": len(policies), "policies": policies},
                              ensure_ascii=False, default=str)

        elif tool_name == "get_policy_detail":
            from db import get_policy_detail
            result = get_policy_detail(tool_input["product"], tool_input["policy_id"])
            return json.dumps(result, ensure_ascii=False, default=str)

        elif tool_name == "get_users":
            from db import get_users_list
            users = get_users_list()
            return json.dumps({"count": len(users), "users": users},
                              ensure_ascii=False, default=str)

        elif tool_name == "get_user_policies":
            from db import get_user_policies
            result = get_user_policies(tool_input["user_id"])
            return json.dumps(result, ensure_ascii=False, default=str)

        elif tool_name == "get_groups":
            from db import get_groups_list
            groups = get_groups_list()
            return json.dumps({"count": len(groups), "groups": groups},
                              ensure_ascii=False, default=str)

        elif tool_name == "get_group_policies":
            from db import get_group_policies
            result = get_group_policies(tool_input["group_id"])
            return json.dumps(result, ensure_ascii=False, default=str)

        elif tool_name == "get_timeline":
            from db import get_policy_timeline
            limit = min(int(tool_input.get("limit", 20)), 50)
            items = get_policy_timeline(limit)
            return json.dumps({"count": len(items), "timeline": items},
                              ensure_ascii=False, default=str)

        elif tool_name == "analyze_policy":
            policy_json = tool_input.get("policy_json", "")
            mode = tool_input.get("mode", "translate")
            query = tool_input.get("query", "")
            parsed = parse_input(policy_json)
            if parsed["policy_count"] == 0:
                return json.dumps({"error": "정책 JSON을 파싱할 수 없습니다"}, ensure_ascii=False)
            product_hint = parsed["products_found"][0] if parsed["products_found"] else ""
            few_shot = _build_few_shot(mode, product_hint)
            if mode == "translate":
                prompt = TRANSLATE_PROMPT
                user_msg = f"{few_shot}다음 정책을 분석해주세요:\n\n{parsed['clean_json']}"
            elif mode == "simulate":
                prompt = SIMULATE_PROMPT
                user_msg = f"{few_shot}시나리오: {query or '일반 시뮬레이션'}\n\n정책:\n{parsed['clean_json']}"
            else:
                prompt = DIAGNOSE_PROMPT
                user_msg = f"{few_shot}다음 정책을 진단해주세요:\n\n{parsed['clean_json']}"
            result = call_claude(prompt, user_msg)
            return json.dumps({"analysis": result, "mode": mode, "product": product_hint},
                              ensure_ascii=False)

        elif tool_name == "search_knowledge":
            try:
                from rag import search
                query = tool_input.get("query", "")
                n = min(int(tool_input.get("n_results", 5)), 10)
                hits = search(query, n_results=n)
                if not hits:
                    return json.dumps({
                        "message": "관련 내용을 찾지 못했습니다. RAG 인덱스가 없거나 비어있습니다.",
                        "hits": []
                    }, ensure_ascii=False)
                return json.dumps({"query": query, "count": len(hits), "hits": hits},
                                  ensure_ascii=False)
            except ImportError:
                return json.dumps({"error": "RAG 모듈 미설치 (chromadb/sentence-transformers)"}, ensure_ascii=False)

        else:
            return json.dumps({"error": f"알 수 없는 도구: {tool_name}"}, ensure_ascii=False)

    except Exception as e:
        logger.error(f"Tool execution error — {tool_name}: {e}")
        return json.dumps({"error": str(e)}, ensure_ascii=False)


# ═══════════════════════════════════════════════════
# 라우트
# ═══════════════════════════════════════════════════

from db import (
    get_dashboard, get_all_policies, get_policy_detail, save_feedback, get_feedback_examples,
    get_unified_policy_full,
    get_users_list, get_groups_list, get_user_policies, get_group_policies,
    get_policy_timeline,
    save_history, get_history,
)
import db as _db_module

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/static/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "OK", "service": "Policy Analyzer", "version": "2.0", "products": 6})

@app.route('/api/translate', methods=['POST'])
@limiter.limit("20 per minute")
def translate_policy():
    try:
        data = request.json
        policy_json = data.get('policy', '')
        if not policy_json:
            return jsonify({"error": "정책 JSON을 입력해주세요"}), 400

        # parser.py가 알아서 처리 (깨끗한 JSON이든 더러운 로그든)
        parsed = parse_input(policy_json)
        policy_text = parsed['clean_json']

        if parsed['policy_count'] == 0 and parsed['input_type'] == 'no_json_found':
            return jsonify({"error": "입력에서 정책 데이터를 찾지 못했습니다. JSON 또는 에이전트 로그를 입력해주세요."}), 400

        # 파싱 메타 정보를 프롬프트에 포함
        meta = ""
        if parsed['input_type'] not in ('clean_json', 'clean_json_array'):
            meta = f"\n[파서 정보] 입력유형: {parsed['input_type']}, 추출 정책: {parsed['policy_count']}개, 제품: {', '.join(parsed['products_found'])}\n"

        # Few-Shot 예시 주입
        product_hint = parsed['products_found'][0] if parsed['products_found'] else ''
        few_shot = _build_few_shot('translate', product_hint)

        user_msg = f"{few_shot}{meta}\n아래 정책 데이터를 분석하여 자연어로 번역해주세요:\n\n{policy_text}"
        result = call_claude(TRANSLATE_PROMPT, user_msg)
        try:
            save_history('translate', product_hint, policy_text[:200], result)
        except Exception:
            pass
        return jsonify({
            "success": True,
            "result": result,
            "feature": "translate",
            "parser_info": {
                "input_type": parsed['input_type'],
                "policy_count": parsed['policy_count'],
                "products": parsed['products_found']
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/simulate', methods=['POST'])
@limiter.limit("20 per minute")
def simulate_policy():
    try:
        data = request.json
        policy_json = data.get('policy', '')
        query = data.get('query', '')
        if not policy_json:
            return jsonify({"error": "정책 JSON을 입력해주세요"}), 400
        if not query:
            return jsonify({"error": "시뮬레이션 질의를 입력해주세요"}), 400

        parsed = parse_input(policy_json)
        policy_text = parsed['clean_json']

        product_hint = parsed['products_found'][0] if parsed['products_found'] else ''
        few_shot = _build_few_shot('simulate', product_hint)

        user_msg = f"{few_shot}정책 데이터:\n{policy_text}\n\n사용자 질의:\n{query}"
        result = call_claude(SIMULATE_PROMPT, user_msg)
        try:
            save_history('simulate', product_hint, f"[{query}] {policy_text[:150]}", result)
        except Exception:
            pass
        return jsonify({"success": True, "result": result, "feature": "simulate"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/diagnose', methods=['POST'])
@limiter.limit("20 per minute")
def diagnose_policy():
    try:
        data = request.json
        policy_json = data.get('policy', '')
        if not policy_json:
            return jsonify({"error": "정책 JSON을 입력해주세요"}), 400

        parsed = parse_input(policy_json)
        policy_text = parsed['clean_json']

        if parsed['policy_count'] == 0 and parsed['input_type'] == 'no_json_found':
            return jsonify({"error": "입력에서 정책 데이터를 찾지 못했습니다."}), 400

        product_hint = parsed['products_found'][0] if parsed['products_found'] else ''
        few_shot = _build_few_shot('diagnose', product_hint)

        user_msg = f"{few_shot}아래 정책 데이터를 진단해주세요:\n\n{policy_text}"
        result = call_claude(DIAGNOSE_PROMPT, user_msg)
        try:
            save_history('diagnose', product_hint, policy_text[:200], result)
        except Exception:
            pass
        return jsonify({"success": True, "result": result, "feature": "diagnose"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Phase 3-4: 역방향 정책 생성 ───

GENERATE_PROMPT = """당신은 이노티움 보안 플랫폼 정책 설계 전문가입니다.
사용자의 요구사항을 받아 **관리자 콘솔 UI 기준 설정 가이드**를 제공합니다.

출력 형식:
1. **설정 목표** — 요구사항을 한 줄로 요약
2. **설정 경로 (단계별)** — 아래 형식으로 각 항목을 나열:
   ```
   [메뉴] > [탭/섹션] > [항목명]
   → 설정값: ON / 블랙리스트 / "txt,exe" 등
   → 효과: 이 설정이 적용되면 어떤 동작이 발생하는지
   → 주의: 잘못 설정 시 발생할 수 있는 문제
   ```
3. **설정 후 확인 사항** — 적용 확인 방법
4. **참고 JSON 필드** (접기 가능한 형태로, 부차적으로만 제공)

규칙:
- JSON을 먼저 보여주지 말 것 — UI 네비게이션 안내가 우선
- 실무자가 콘솔에서 바로 따라할 수 있게 구체적인 경로 명시
- 설정값 예시를 반드시 포함
- 지원 제품: SecureZone, RansomCruncher, nPouch, innoECM, LizardBackup, innoMark"""

CONFLICT_PROMPT = """당신은 이노티움 보안 정책 충돌 탐지 전문가입니다.
입력된 정책 JSON에서 다음을 분석해주세요:

1. **내부 충돌**: 같은 정책 내 서로 모순되는 설정 (예: 허용과 차단이 동시에 활성화)
2. **논리적 불일치**: 상위 설정이 비활성화인데 하위 세부 설정이 활성화된 경우
3. **보안 취약점**: 보안을 약화시키는 설정 조합
4. **권고 수정사항**: 각 충돌/이슈별 구체적인 수정 방법

마크다운 형식으로, 심각도(🔴 위험 / 🟡 주의 / 🟢 정보)를 표시해주세요."""

BULK_DIAGNOSE_PROMPT = """당신은 이노티움 보안 플랫폼 전체 정책 감사 전문가입니다.
아래 제공된 여러 정책들을 종합 분석하여 다음을 제공해주세요:

1. **전체 보안 점수** (0~100점) 및 등급 (A~F)
2. **제품별 요약**: 각 제품 정책의 보안 수준 요약
3. **공통 취약점**: 여러 정책에서 반복되는 문제점
4. **우선 조치 항목**: 즉시 수정이 필요한 Top 5 이슈
5. **전체 권고사항**: 보안 강화를 위한 종합 제안

마크다운 형식으로 경영진/기술팀 모두가 이해할 수 있게 작성하세요."""

@app.route('/api/generate', methods=['POST'])
@limiter.limit("10 per minute")
def api_generate():
    try:
        data = request.json or {}
        requirements = data.get('requirements', '').strip()
        product = data.get('product', '').strip()
        if not requirements:
            return jsonify({"error": "정책 요구사항을 입력해주세요"}), 400

        product_context = f"대상 제품: {product}\n" if product else ""
        user_msg = f"{product_context}요구사항:\n{requirements}\n\n위 요구사항에 맞는 정책 JSON 초안을 생성해주세요."
        result = call_claude(GENERATE_PROMPT, user_msg)
        try:
            save_history('generate', product, requirements[:200], result)
        except Exception:
            pass
        return jsonify({"success": True, "result": result, "feature": "generate"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Phase 3-4: 정책 충돌 탐지 ───

@app.route('/api/conflict', methods=['POST'])
@limiter.limit("20 per minute")
def api_conflict():
    try:
        data = request.json or {}
        policy_json = data.get('policy', '').strip()
        if not policy_json:
            return jsonify({"error": "정책 JSON을 입력해주세요"}), 400

        parsed = parse_input(policy_json)
        if parsed['policy_count'] == 0 and parsed['input_type'] == 'no_json_found':
            return jsonify({"error": "정책 JSON을 찾을 수 없습니다"}), 400

        product_hint = parsed['products_found'][0] if parsed['products_found'] else ''
        user_msg = f"다음 정책에서 충돌 및 보안 이슈를 탐지해주세요:\n\n{parsed['clean_json']}"
        result = call_claude(CONFLICT_PROMPT, user_msg)
        try:
            save_history('conflict', product_hint, parsed['clean_json'][:200], result)
        except Exception:
            pass
        return jsonify({"success": True, "result": result, "feature": "conflict"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Phase 3-4: 벌크 진단 리포트 ───

ZIP_ANALYZE_PROMPT = """당신은 이노티움 보안 플랫폼 전체 정책 감사 전문가입니다.
아래는 ZIP에서 추출한 실제 정책 JSON 파일들입니다. 현재 실제로 적용된 정책들을 종합 분석하세요.

분석 항목:
1. **정책 구성 요약** — 어떤 제품의 정책이 몇 개 있는지, 전체 구조 파악
2. **제품별 상세 분석** — 각 정책의 핵심 설정값과 보안 수준 (ON/OFF 여부, 임계값, 모드)
3. **전체 보안 점수** (0~100점) 및 등급 (A~F) — 설정 완성도 기준
4. **위험 설정 목록** — 🔴 즉시 수정 / 🟡 검토 필요 항목 나열
5. **정책 간 연관성** — 제품 간 설정이 상호 영향을 주는 부분 (예: SecureZone ↔ nPouch 연동)
6. **권고 조치** — 우선순위 순으로 Top 5 개선사항

실제 JSON 값을 근거로 구체적인 필드명과 설정값을 언급하며 분석하세요."""


@app.route('/api/upload-zip-analyze', methods=['POST'])
@limiter.limit("5 per minute")
def api_upload_zip_analyze():
    """ZIP 파일에서 JSON 정책 파일 추출 → 전체 종합 분석"""
    try:
        f = request.files.get('file')
        if not f or not f.filename:
            return jsonify({"error": "ZIP 파일을 업로드해주세요"}), 400
        if not f.filename.lower().endswith('.zip'):
            return jsonify({"error": "ZIP 파일만 지원합니다"}), 400

        import zipfile, io as _io
        raw = f.read()
        MAX_PER_FILE = 8000   # JSON 파일당 최대 글자
        MAX_TOTAL    = 50000  # 전체 합산 최대 글자

        parts = []
        file_list = []
        total_chars = 0

        try:
            with zipfile.ZipFile(_io.BytesIO(raw)) as zf:
                members = sorted(
                    [m for m in zf.infolist() if not m.is_dir()],
                    key=lambda m: m.filename
                )
                for member in members:
                    ext = os.path.splitext(member.filename)[1].lower()
                    if ext not in ('.json', '.txt'):
                        continue
                    try:
                        text = zf.read(member.filename).decode('utf-8', errors='replace').strip()
                    except Exception:
                        continue
                    if not text:
                        continue

                    # 제품 자동 감지
                    try:
                        from parser import detect_product
                        product = detect_product(text) or '알 수 없음'
                    except Exception:
                        product = '알 수 없음'

                    if len(text) > MAX_PER_FILE:
                        text = text[:MAX_PER_FILE] + "\n... (이하 생략)"

                    short_name = os.path.basename(member.filename)
                    parts.append(
                        f"=== 파일: {short_name} | 감지 제품: {product} ===\n{text}"
                    )
                    file_list.append(f"{short_name} ({product})")
                    total_chars += len(text)

                    if total_chars >= MAX_TOTAL:
                        parts.append("[전체 용량 한도 도달 — 이후 파일 생략]")
                        break
        except zipfile.BadZipFile:
            return jsonify({"error": "ZIP 파일이 손상되었거나 올바르지 않습니다"}), 400

        if not parts:
            return jsonify({"error": "ZIP 안에 분석 가능한 JSON 정책 파일이 없습니다"}), 400

        file_summary = ", ".join(file_list)
        user_msg = (
            f"업로드된 ZIP: {f.filename}\n"
            f"추출된 정책 파일 {len(file_list)}개: {file_summary}\n\n"
            + "\n\n".join(parts)
        )

        result = call_claude(ZIP_ANALYZE_PROMPT, user_msg, model=CHAT_MODEL_NAME)
        try:
            save_history('bulk', '', f"ZIP: {f.filename} ({len(file_list)}개)", result)
        except Exception:
            pass
        return jsonify({
            "success": True,
            "result": result,
            "feature": "zip_analyze",
            "stats": {"files": len(file_list), "file_list": file_list}
        })
    except Exception as e:
        logger.error(f"ZIP 분석 오류: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/bulk-diagnose', methods=['POST'])
@limiter.limit("3 per minute")
def api_bulk_diagnose():
    try:
        # DB에서 전체 제품 정책 수집 (각 제품 최대 5개)
        all_policies = get_all_policies()
        collected = {}
        for prod, items in all_policies.items():
            if items:
                collected[prod] = items[:5]

        if not collected:
            return jsonify({"error": "진단할 정책이 없습니다. DB에 정책을 먼저 등록해주세요."}), 404

        # 정책 요약 텍스트 구성
        summary_lines = []
        total = 0
        for prod, items in collected.items():
            summary_lines.append(f"\n### {prod} ({len(items)}개 정책)")
            for p in items:
                summary_lines.append(f"- [{p['id']}] {p['name']}")
                total += 1

        policy_summary = "\n".join(summary_lines)
        user_msg = (
            f"총 {total}개 정책 ({len(collected)}개 제품) 벌크 진단 요청\n"
            f"{policy_summary}\n\n"
            "위 정책 현황을 기반으로 전체 보안 감사 리포트를 작성해주세요. "
            "각 제품의 정책 수와 구성에 대한 분석을 포함하세요."
        )
        result = call_claude(BULK_DIAGNOSE_PROMPT, user_msg)
        try:
            save_history('bulk', '', f"{len(collected)}개 제품 {total}개 정책", result)
        except Exception:
            pass
        return jsonify({
            "success": True,
            "result": result,
            "feature": "bulk",
            "stats": {"products": len(collected), "policies": total}
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Phase 3-2: 정책 비교 Diff ───

DIFF_PROMPT = """당신은 이노티움 보안 정책 비교 전문가입니다.
두 정책을 비교하여 변경된 항목, 추가된 항목, 삭제된 항목을 명확하게 설명해주세요.
보안에 영향을 미치는 중요한 변경사항을 강조하고, 실무적 의미를 한국어로 설명해주세요."""

@app.route('/api/diff', methods=['POST'])
@limiter.limit("20 per minute")
def api_diff():
    try:
        data = request.json
        policy_a = data.get('policy_a', '').strip()
        policy_b = data.get('policy_b', '').strip()
        if not policy_a or not policy_b:
            return jsonify({"error": "두 정책 JSON을 모두 입력해주세요"}), 400

        parsed_a = parse_input(policy_a)
        parsed_b = parse_input(policy_b)
        product = (parsed_a['products_found'] or parsed_b['products_found'] or [''])[0]

        user_msg = (
            f"## 정책 A (기준)\n\n{parsed_a['clean_json']}\n\n"
            f"## 정책 B (비교)\n\n{parsed_b['clean_json']}\n\n"
            "위 두 정책의 차이점을 분석해주세요."
        )
        result = call_claude(DIFF_PROMPT, user_msg)
        try:
            save_history('diff', product, f"A:{policy_a[:100]} / B:{policy_b[:100]}", result)
        except Exception:
            pass
        return jsonify({"success": True, "result": result, "feature": "diff"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Phase 3-2: 에이전트 로그 업로드 분석 ───

LOG_UPLOAD_PROMPT = """당신은 이노티움 보안 솔루션 에이전트 로그 분석 전문가입니다.
업로드된 에이전트 로그 파일에서:
1. 오류(ERROR) 및 경고(WARN) 항목 목록
2. 주요 이상 패턴 (반복 오류, 예외, 실패 등)
3. 원인 추정 및 조치 권고사항
를 한국어로 명확하게 정리해주세요. 마크다운 형식으로 작성하세요."""

def _extract_zip_logs(file_bytes):
    """ZIP 파일에서 텍스트 로그 파일들을 추출하여 하나의 문자열로 합침.
    지원 확장자: .log .txt .json .cst (및 확장자 없는 파일)
    실행파일·이미지 등 바이너리는 건너뜀.
    """
    import zipfile, io
    ALLOWED_EXT = {'.log', '.txt', '.json', '.cst', ''}
    MAX_PER_FILE = 15000   # 파일당 최대 글자 수
    MAX_TOTAL    = 50000   # 전체 합산 최대 글자 수

    parts = []
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            members = [m for m in zf.infolist() if not m.is_dir()]
            # 파일명 기준 정렬 (날짜순 파일명이면 순서 유지)
            members.sort(key=lambda m: m.filename)
            for member in members:
                ext = os.path.splitext(member.filename)[1].lower()
                if ext not in ALLOWED_EXT:
                    continue
                try:
                    raw = zf.read(member.filename)
                    text = raw.decode('utf-8', errors='replace')
                except Exception:
                    continue
                if not text.strip():
                    continue
                # 파일당 상한 — 끝부분 우선 (최신 로그)
                if len(text) > MAX_PER_FILE:
                    text = f"[앞부분 생략]\n" + text[-MAX_PER_FILE:]
                parts.append(f"=== {member.filename} ===\n{text}")
                total += len(text)
                if total >= MAX_TOTAL:
                    parts.append("[전체 용량 한도 도달 — 이후 파일 생략]")
                    break
    except zipfile.BadZipFile:
        return None, "ZIP 파일이 손상되었거나 올바르지 않습니다"
    if not parts:
        return None, "ZIP 안에 분석 가능한 로그 파일(.log .json .txt .cst)이 없습니다"
    return "\n\n".join(parts), None


@app.route('/api/upload-log', methods=['POST'])
@limiter.limit("10 per minute")
def api_upload_log():
    try:
        # multipart 파일 업로드 또는 JSON 텍스트
        if request.files.get('file'):
            f = request.files['file']
            if not f.filename:
                return jsonify({"error": "파일명이 없습니다"}), 400
            filename = f.filename
            raw_bytes = f.read()

            # ZIP 파일 처리
            if filename.lower().endswith('.zip'):
                content, err = _extract_zip_logs(raw_bytes)
                if err:
                    return jsonify({"error": err}), 400
                filename_label = filename + " (압축 해제)"
            else:
                content = raw_bytes.decode('utf-8', errors='replace')
                filename_label = filename
                # 단일 파일 50000자 상한
                if len(content) > 50000:
                    content = "[앞부분 생략 — 마지막 50000자]\n\n" + content[-50000:]
        else:
            data = request.json or {}
            content = data.get('content', '')
            filename_label = data.get('filename', 'log.txt')

        if not content.strip():
            return jsonify({"error": "로그 내용이 비어 있습니다"}), 400

        query = request.form.get('query', '') if request.files.get('file') else (request.json or {}).get('query', '')

        if query:
            user_msg = f"파일: {filename_label}\n질의: {query}\n\n로그 내용:\n{content}"
        else:
            user_msg = f"파일: {filename_label}\n\n로그 내용:\n{content}"

        result = call_claude(LOG_UPLOAD_PROMPT, user_msg, model=CHAT_MODEL_NAME)
        try:
            save_history('log', '', filename_label, result)
        except Exception:
            pass
        return jsonify({"success": True, "result": result, "filename": filename_label})
    except Exception as e:
        logger.error(f"upload-log 오류: {e}")
        return jsonify({"error": str(e)}), 500


# ─── Phase 3-2: 분석 이력 조회 ───

@app.route('/api/history', methods=['GET'])
def api_history():
    try:
        limit = min(int(request.args.get('limit', 20)), 50)
        rows = get_history(limit)
        return jsonify({"history": rows})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── DB 엔드포인트 ───

@app.route('/api/dashboard', methods=['GET'])
def api_dashboard():
    try:
        return jsonify(get_dashboard())
    except Exception as e:
        return jsonify({"error": str(e), "connected": False}), 500

@app.route('/api/policies', methods=['GET'])
def api_policies():
    try:
        return jsonify(get_all_policies())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/policies/<product>', methods=['GET'])
def api_policies_by_product(product):
    try:
        all_data = get_all_policies()
        if 'error' in all_data:
            return jsonify(all_data), 500
        policies = all_data.get(product, [])
        return jsonify({"policies": policies, "product": product, "count": len(policies)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/policies/<product>/<int:policy_id>', methods=['GET'])
def api_policy_detail(product, policy_id):
    try:
        result = get_policy_detail(product, policy_id)
        if 'error' in result:
            return jsonify(result), 404
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Phase 3-1: 챗봇 엔드포인트 ───

@app.route('/api/chat', methods=['POST'])
@limiter.limit("30 per minute")
def api_chat():
    """Claude tool_use 기반 챗봇 — 멀티턴 + DB 도구 호출"""
    try:
        data = request.json
        user_message = (data.get('message') or '').strip()
        history = data.get('history') or []
        image_data = data.get('image')  # {data: base64str, type: 'image/jpeg'}

        if not user_message:
            return jsonify({"error": "message가 필요합니다"}), 400

        # 히스토리 최대 10턴(20개 메시지)으로 truncate — 토큰 절약
        if len(history) > 20:
            history = history[-20:]

        # 이미지 첨부 처리
        if image_data and image_data.get('data') and image_data.get('type'):
            user_content = [
                {"type": "image", "source": {
                    "type": "base64",
                    "media_type": image_data['type'],
                    "data": image_data['data']
                }},
                {"type": "text", "text": user_message}
            ]
        else:
            user_content = user_message
        messages = history + [{"role": "user", "content": user_content}]

        MAX_LOOPS = 5
        tool_calls_made = []

        for _ in range(MAX_LOOPS):
            response = client.messages.create(
                model=CHAT_MODEL_NAME,
                max_tokens=8192,
                temperature=0.3,
                system=get_chat_system_prompt(),
                tools=CHAT_TOOLS,
                messages=messages,
            )

            if response.stop_reason == "end_turn":
                # 텍스트 응답 추출
                text = ""
                for block in response.content:
                    if hasattr(block, "text"):
                        text += block.text
                # 최종 히스토리 구성 (직렬화 가능한 형태로)
                messages.append({
                    "role": "assistant",
                    "content": [{"type": "text", "text": text}]
                })
                logger.info(f"Chat 응답 완료 — 도구 호출: {tool_calls_made}")
                return jsonify({
                    "result": text,
                    "history": messages,
                    "tools_used": tool_calls_made,
                })

            if response.stop_reason == "tool_use":
                # 어시스턴트 메시지 (tool_use 블록 포함) 추가
                assistant_content = []
                tool_result_content = []

                for block in response.content:
                    if block.type == "text":
                        assistant_content.append({"type": "text", "text": block.text})
                    elif block.type == "tool_use":
                        assistant_content.append({
                            "type": "tool_use",
                            "id": block.id,
                            "name": block.name,
                            "input": block.input,
                        })
                        # 도구 실행
                        logger.info(f"Tool call: {block.name} input={block.input}")
                        tool_calls_made.append(block.name)
                        tool_result = _execute_tool(block.name, block.input)
                        tool_result_content.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": tool_result,
                        })

                messages.append({"role": "assistant", "content": assistant_content})
                messages.append({"role": "user", "content": tool_result_content})
            else:
                # 예상치 못한 stop_reason
                break

        # MAX_LOOPS 초과 시 마지막 텍스트 반환
        final_text = "죄송합니다, 처리 중 문제가 발생했습니다. 다시 질문해 주세요."
        return jsonify({"result": final_text, "history": messages, "tools_used": tool_calls_made})

    except Exception as e:
        logger.error(f"Chat API 오류: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/chat/correction', methods=['POST'])
@limiter.limit("20 per minute")
def api_chat_correction():
    """챗봇 오답 수정 저장"""
    try:
        data = request.json
        question = data.get('question', '').strip()
        wrong_answer = data.get('wrong_answer', '').strip()
        correction = data.get('correction', '').strip()
        if not correction:
            return jsonify({"error": "수정 내용을 입력하세요"}), 400

        # Claude로 자연어 수정을 구조화
        structured_prompt = f"""아래 오답 수정 내용을 간결하고 명확한 한국어 사실 문장으로 정리해주세요.
원래 질문: {question[:200]}
잘못된 답변 요약: {wrong_answer[:300]}
사용자 수정 내용: {correction}

출력: 핵심 사실만 2~4문장으로 정리 (예: "제어스위트의 controlSuiteProcessList는 ...")"""

        structured = call_claude("당신은 정보 정리 도우미입니다. 핵심만 간결하게 정리하세요.", structured_prompt)
        save_correction(question, wrong_answer, correction, structured)
        logger.info(f"오답 수정 저장 — 질문: {question[:50]}")
        return jsonify({"success": True, "structured": structured})
    except Exception as e:
        logger.error(f"오답 수정 저장 오류: {e}")
        return jsonify({"error": str(e)}), 500


# ─── 피드백 엔드포인트 (Few-Shot 예제 축적) ───

@app.route('/api/feedback', methods=['POST'])
def api_feedback():
    try:
        data = request.json
        policy_json = data.get('policy', '')
        result = data.get('result', '')
        feature = data.get('feature', '')
        rating = int(data.get('rating', 0))
        product = data.get('product', '')

        if not policy_json or not result or not feature or rating not in (1, -1):
            return jsonify({"error": "필드 누락 또는 잘못된 rating (1/-1)"}), 400

        save_feedback(policy_json, result, feature, rating, product)
        logger.info(f"피드백 저장 — feature={feature}, rating={rating}, product={product}")
        return jsonify({"success": True})
    except Exception as e:
        logger.error(f"피드백 저장 오류: {e}")
        return jsonify({"error": str(e)}), 500


# ─── Phase 2-1: 통합 정책 조립 ───

@app.route('/api/policies/<product>/<int:policy_id>/full', methods=['GET'])
def api_policy_full(product, policy_id):
    """통합 정책 전체 조립 (unified + 연결 제품 정책 JOIN)"""
    try:
        if product != 'unified':
            return jsonify({"error": "통합 정책 조립은 unified 제품만 지원합니다"}), 400
        result = get_unified_policy_full(policy_id)
        if 'error' in result:
            return jsonify(result), 404
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Phase 2-2: 사용자/부서별 정책 조회 ───

@app.route('/api/users', methods=['GET'])
def api_users():
    """실 사용자 목록 (member_status=1)"""
    try:
        return jsonify({"users": get_users_list()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/users/<int:user_id>/policies', methods=['GET'])
def api_user_policies(user_id):
    """특정 사용자의 할당 정책"""
    try:
        result = get_user_policies(user_id)
        if 'error' in result:
            return jsonify(result), 404
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/groups', methods=['GET'])
def api_groups():
    """부서/그룹 목록"""
    try:
        return jsonify({"groups": get_groups_list()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/groups/<int:group_id>/policies', methods=['GET'])
def api_group_policies(group_id):
    """특정 부서의 할당 정책"""
    try:
        result = get_group_policies(group_id)
        if 'error' in result:
            return jsonify(result), 404
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Phase 2-4: 정책 변경 이력 타임라인 ───

@app.route('/api/timeline', methods=['GET'])
def api_timeline():
    """전체 정책 테이블의 최근 변경 이력"""
    try:
        limit = min(int(request.args.get('limit', 30)), 100)
        return jsonify({"timeline": get_policy_timeline(limit)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── 로그 파일 엔드포인트 ───

ALLOWED_LOG_DIRS = [
    '/log/catalina/',
    '/cache/agentLog/',
    '/log/nginx/',
]

@app.route('/api/logs/list', methods=['GET'])
def api_logs_list():
    import glob
    groups = {'catalina': [], 'agent': [], 'nginx': [], 'other': []}
    dir_group_map = {
        '/log/catalina/': 'catalina',
        '/cache/agentLog/': 'agent',
        '/log/nginx/': 'nginx',
    }
    for log_dir in ALLOWED_LOG_DIRS:
        if not os.path.isdir(log_dir):
            continue
        group_key = dir_group_map.get(log_dir, 'other')
        for path in glob.glob(os.path.join(log_dir, '**', '*'), recursive=True):
            real = os.path.realpath(path)
            if not any(real.startswith(os.path.realpath(d)) for d in ALLOWED_LOG_DIRS):
                continue
            if os.path.isfile(real):
                stat = os.stat(real)
                groups[group_key].append({
                    'path': path,
                    'name': os.path.basename(path),
                    'size': stat.st_size,
                    'modified': stat.st_mtime,
                })
    for key in groups:
        groups[key].sort(key=lambda x: x['modified'], reverse=True)
    return jsonify({'groups': groups})

@app.route('/api/logs/analyze', methods=['POST'])
def api_logs_analyze():
    try:
        data = request.json
        log_path = data.get('path') or data.get('logPath', '')
        query = data.get('query', '')

        if not log_path:
            return jsonify({"error": "logPath가 필요합니다"}), 400

        real_path = os.path.realpath(log_path)
        allowed = any(real_path.startswith(os.path.realpath(d)) for d in ALLOWED_LOG_DIRS)
        if not allowed:
            return jsonify({"error": "허용되지 않은 경로입니다"}), 403

        if not os.path.isfile(real_path):
            return jsonify({"error": "파일을 찾을 수 없습니다"}), 404

        with open(real_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        if len(content) > 50000:
            content = content[-50000:]  # tail

        if query:
            user_msg = f"다음 로그에서 '{query}'를 찾아 분석해줘:\n\n{content}"
        else:
            user_msg = f"다음 로그의 오류/경고/이상 항목을 분석해줘:\n\n{content}"

        system = "당신은 이노티움 보안 솔루션 서버 로그 분석 전문가입니다. 로그에서 오류, 경고, 이상 패턴을 찾아 한국어로 명확하게 설명해주세요."
        result = call_claude(system, user_msg)
        return jsonify({"success": True, "result": result, "file": os.path.basename(log_path)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Phase 3-3: RAG 엔드포인트 ───

@app.route('/api/rag/status', methods=['GET'])
def api_rag_status():
    """RAG 인덱스 상태 확인"""
    try:
        from rag import get_status
        return jsonify(get_status())
    except ImportError:
        return jsonify({"status": "unavailable", "message": "chromadb/sentence-transformers 미설치"}), 503
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/rag/build', methods=['POST'])
def api_rag_build():
    """docs/manuals/ 디렉토리의 모든 PDF로 RAG 인덱스 빌드 (관리자용)"""
    try:
        from rag import build_index
        data = request.json or {}
        pdf_path = data.get('pdf_path') or None

        # 경로 주입 방지: pdf_path 지정 시 docs/ 하위만 허용
        if pdf_path:
            real = os.path.realpath(pdf_path)
            allowed_prefixes = [
                os.path.realpath('./docs'),
                os.path.realpath('/app/policy-analyzer/docs'),
            ]
            if not any(real.startswith(p) for p in allowed_prefixes):
                return jsonify({"error": "허용되지 않은 PDF 경로입니다"}), 403
            result = build_index(pdf_path=pdf_path)
        else:
            # 기본: docs/manuals/ 디렉토리 전체 스캔
            result = build_index()

        return jsonify(result)
    except ImportError:
        return jsonify({"error": "chromadb/sentence-transformers 미설치"}), 503
    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        logger.error(f"RAG build 오류: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/rag/search', methods=['POST'])
def api_rag_search():
    """RAG 키워드 검색 (직접 테스트용)"""
    try:
        from rag import search
        data = request.json or {}
        query = (data.get('query') or '').strip()
        if not query:
            return jsonify({"error": "query가 필요합니다"}), 400
        n = min(int(data.get('n_results', 5)), 10)
        hits = search(query, n_results=n)
        return jsonify({"query": query, "count": len(hits), "hits": hits})
    except ImportError:
        return jsonify({"error": "chromadb/sentence-transformers 미설치"}), 503
    except Exception as e:
        logger.error(f"RAG search 오류: {e}")
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════
# Word 문서 내보내기 (markdown → .docx)
# ═══════════════════════════════════════════════════

def _markdown_to_docx(markdown_text):
    """마크다운 텍스트를 python-docx Document 객체로 변환 (한국어 폰트 완전 지원)"""
    from docx import Document
    from docx.shared import Pt, RGBColor, Inches
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement
    import io

    FONT = 'Malgun Gothic'   # 한국어 기본 폰트

    # ── 핵심 헬퍼: 한국어 포함 모든 문자에 폰트 적용 ──
    # run.font.name 은 라틴 폰트(w:ascii)만 바꾸므로 한국어가 깨짐
    # w:eastAsia 를 XML로 직접 설정해야 한국어가 제대로 표시됨
    def _set_font(run, size_pt=10, bold=None, color=None):
        # XML rFonts 요소에 ascii·hAnsi·eastAsia·cs 모두 지정
        rPr = run._r.get_or_add_rPr()
        rFonts = rPr.find(qn('w:rFonts'))
        if rFonts is None:
            rFonts = OxmlElement('w:rFonts')
            rPr.insert(0, rFonts)
        for attr in ('w:ascii', 'w:hAnsi', 'w:eastAsia', 'w:cs'):
            rFonts.set(qn(attr), FONT)
        run.font.size = Pt(size_pt)
        if bold is not None:
            run.bold = bold
        if color:
            run.font.color.rgb = color

    # ── 문서 기본 폰트도 eastAsia 포함하여 설정 ──
    def _set_doc_default_font(doc):
        styles_el = doc.styles.element
        docDefaults = styles_el.find(qn('w:docDefaults'))
        if docDefaults is None:
            docDefaults = OxmlElement('w:docDefaults')
            styles_el.insert(0, docDefaults)
        rPrDef = docDefaults.find(qn('w:rPrDefault'))
        if rPrDef is None:
            rPrDef = OxmlElement('w:rPrDefault')
            docDefaults.append(rPrDef)
        rPr = rPrDef.find(qn('w:rPr'))
        if rPr is None:
            rPr = OxmlElement('w:rPr')
            rPrDef.append(rPr)
        rFonts = rPr.find(qn('w:rFonts'))
        if rFonts is None:
            rFonts = OxmlElement('w:rFonts')
            rPr.insert(0, rFonts)
        for attr in ('w:ascii', 'w:hAnsi', 'w:eastAsia', 'w:cs'):
            rFonts.set(qn(attr), FONT)
        # 기본 크기
        sz = rPr.find(qn('w:sz'))
        if sz is None:
            sz = OxmlElement('w:sz'); rPr.append(sz)
        sz.set(qn('w:val'), '20')   # 10pt = 20 half-points
        szCs = rPr.find(qn('w:szCs'))
        if szCs is None:
            szCs = OxmlElement('w:szCs'); rPr.append(szCs)
        szCs.set(qn('w:val'), '20')

    doc = Document()
    _set_doc_default_font(doc)

    section = doc.sections[0]
    section.left_margin   = Inches(1.0)
    section.right_margin  = Inches(1.0)
    section.top_margin    = Inches(1.0)
    section.bottom_margin = Inches(1.0)

    # Normal 스타일 기본 크기
    doc.styles['Normal'].font.size = Pt(10)

    lines = markdown_text.split('\n')

    # ── 이모지 · 4바이트 유니코드 제거 (docx 렌더 오류 방지) ──
    def _clean(text):
        return re.sub(r'[\U00010000-\U0010FFFF]', '', text)

    # ── **bold** 파싱하여 run 분리 추가 ──
    def _add_runs(para, text, size_pt=10, color=None):
        text = re.sub(r'`([^`]+)`', r'\1', text)   # 인라인 코드 역따옴표 제거
        text = _clean(text)
        parts = re.split(r'\*\*(.*?)\*\*', text)
        for idx, part in enumerate(parts):
            if not part:
                continue
            run = para.add_run(part)
            _set_font(run, size_pt=size_pt, bold=(idx % 2 == 1), color=color)

    def add_heading(text, level):
        clean = re.sub(r'^#+\s*', '', text).strip()
        clean = _clean(clean)
        para = doc.add_heading('', level=level)
        colors = {1: RGBColor(0x1a,0x56,0x76), 2: RGBColor(0x1a,0x56,0x76),
                  3: RGBColor(0x22,0x66,0x99), 4: RGBColor(0x44,0x44,0x44)}
        sizes  = {1: 16, 2: 13, 3: 11, 4: 10}
        run = para.add_run(clean)
        _set_font(run, size_pt=sizes.get(level, 10),
                  bold=True, color=colors.get(level))

    def add_paragraph_with_markup(text):
        para = doc.add_paragraph()
        para.paragraph_format.space_after = Pt(2)
        _add_runs(para, text, size_pt=10)
        return para

    def add_bullet(text):
        clean = re.sub(r'^[-*]\s+', '', text).strip()
        para = doc.add_paragraph(style='List Bullet')
        _add_runs(para, clean, size_pt=10)

    def flush_table(rows):
        if len(rows) < 1:
            return
        col_count = max(len(r) for r in rows)
        t = doc.add_table(rows=0, cols=col_count)
        t.style = 'Table Grid'
        data_rows = [r for ri, r in enumerate(rows)
                     if not (ri == 1 and all(set(c.strip()) <= set('-| ') for c in r))]
        for ri, row_cells in enumerate(data_rows):
            tr = t.add_row()
            for ci in range(col_count):
                cell_text = row_cells[ci].strip() if ci < len(row_cells) else ''
                cell_text = re.sub(r'\*\*(.*?)\*\*', r'\1', cell_text)
                cell_text = _clean(cell_text)
                c = tr.cells[ci]
                c.text = ''
                run = c.paragraphs[0].add_run(cell_text)
                _set_font(run, size_pt=9, bold=(ri == 0))
        doc.add_paragraph()

    table_rows = []
    in_table   = False

    i = 0
    while i < len(lines):
        stripped = lines[i].strip()

        if not stripped:
            if in_table and table_rows:
                flush_table(table_rows)
                table_rows = []; in_table = False
            i += 1
            continue

        if re.match(r'^-{3,}$', stripped):
            if in_table and table_rows:
                flush_table(table_rows)
                table_rows = []; in_table = False
            doc.add_paragraph()
            i += 1
            continue

        if stripped.startswith('|') and stripped.endswith('|'):
            in_table = True
            table_rows.append([c.strip() for c in stripped.split('|')[1:-1]])
            i += 1
            continue

        if in_table and table_rows:
            flush_table(table_rows)
            table_rows = []; in_table = False

        m = re.match(r'^(#{1,4})\s', stripped)
        if m:
            add_heading(stripped, len(m.group(1)))
        elif stripped.startswith('>'):
            clean = _clean(re.sub(r'^>\s*', '', stripped))
            para = doc.add_paragraph(style='Quote')
            run = para.add_run(re.sub(r'\*\*(.*?)\*\*', r'\1', clean))
            _set_font(run, size_pt=9)
        elif re.match(r'^[-*]\s', stripped):
            add_bullet(stripped)
        else:
            add_paragraph_with_markup(stripped)

        i += 1

    if in_table and table_rows:
        flush_table(table_rows)

    buf = io.BytesIO()
    doc.save(buf)
    buf.seek(0)
    return buf


@app.route('/api/export-docx', methods=['POST'])
def export_docx():
    """마크다운 분석 결과를 Word(.docx)로 변환하여 다운로드"""
    try:
        data = request.get_json(force=True)
        markdown_text = data.get('markdown', '').strip()
        raw_filename   = data.get('filename', '정책분석결과')
        # 파일명 안전 처리
        safe_name = re.sub(r'[\\/:*?"<>|]', '_', raw_filename)
        filename  = safe_name + '.docx'

        if not markdown_text:
            return jsonify({'error': '변환할 내용이 없습니다'}), 400

        # 방법 1: pypandoc (pandoc 설치된 경우 최고 품질)
        try:
            import pypandoc, tempfile, os
            tmp = tempfile.NamedTemporaryFile(suffix='.docx', delete=False)
            tmp.close()
            pypandoc.convert_text(
                markdown_text, 'docx', format='markdown',
                outputfile=tmp.name,
                extra_args=['--standalone']
            )
            response = send_file(
                tmp.name, as_attachment=True,
                download_name=filename,
                mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            )
            @response.call_on_close
            def cleanup():
                try: os.unlink(tmp.name)
                except Exception: pass
            return response
        except (ImportError, Exception):
            pass  # fallback to python-docx

        # 방법 2: python-docx 자체 변환
        buf = _markdown_to_docx(markdown_text)
        return send_file(
            buf, as_attachment=True,
            download_name=filename,
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        )

    except ImportError:
        return jsonify({'error': 'python-docx 미설치. pip install python-docx 후 재시도'}), 503
    except Exception as e:
        logger.error(f"export-docx 오류: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
