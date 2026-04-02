"""
╔══════════════════════════════════════════════════════════════╗
║  Policy Analyzer v3.0 — 보안 정책 번역기 & 시뮬레이터        ║
║  Innotium Security Platform v11                              ║
║  6개 제품 통합 Knowledge Base (매뉴얼 기반 강화)               ║
║  Powered by Claude AI + RAG                                  ║
╚══════════════════════════════════════════════════════════════╝
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import json
import logging
import logging.handlers
from datetime import datetime
from parser import parse_input
import anthropic

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

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
MODEL_NAME = 'claude-sonnet-4-6'

client = anthropic.Anthropic(api_key=API_KEY, timeout=60.0)

logger.info(f"Policy Analyzer v3.0 시작 — 모델: {MODEL_NAME}")
print(f"[✓] Claude 모델: {MODEL_NAME}")
print("[✓] Policy Analyzer v3.0 — 6개 제품 통합 (매뉴얼 기반 KB)")


def call_claude(system_prompt, user_message):
    """Claude API 호출"""
    try:
        logger.info(f"Claude API 호출 — 입력 길이: {len(user_message)}")
        response = client.messages.create(
            model=MODEL_NAME,
            max_tokens=8192,
            temperature=0.3,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}]
        )
        result = response.content[0].text
        logger.info(f"Claude API 완료 — 출력 길이: {len(result)}")
        return result
    except anthropic.APITimeoutError:
        logger.error("Claude API 타임아웃 (60초 초과)")
        return "AI 응답 시간 초과 (60초). 입력이 너무 크거나 서버 부하가 높습니다. 잠시 후 재시도해주세요."
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
| isAllowExtension | 확장자 허용 모드 | 🟠 |
| controlExtension | 제어 확장자 목록 | 🟠 |
| isHeaderCheck | 파일 헤더 검사(위변조 탐지) | 🟠 |
| isSignExcept / signExcept | 디지털서명 예외 | 🟡 |
| controlSuiteProcessList / controlSuiteProcessTagList | 프로세스/태그 제어 목록 | 🔴 |
| controlSuiteWebRestrictList | 웹 제한 목록 | 🟠 |

### 접근제어 정책 (Access Control) — Windows 시스템 기능 제어
| 필드 | 설명 | 보안 |
|------|------|------|
| isAccessControl | 접근제어 활성화 | 🔴 |
| isCmd | CMD 차단 | 🔴 |
| isControlPanel | 제어판 차단 | 🟠 |
| isRegedit | 레지스트리 편집기 차단 | 🔴 |
| isMmc | MMC 콘솔 차단 | 🟠 |
| isHideExplorerRecent | 탐색기 최근 항목 숨김 | 🟡 |
| pickHideDrive | 숨길 드라이브(예:"D,E") | 🟠 |
| pickDenyDrive | 접근 차단 드라이브 | 🔴 |
| pickExceptDrive | 예외 드라이브 | 🟡 |
| usbControlAuth | USB(0:미사용,1:읽기전용,2:차단) | 🔴 |

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

### 개인정보 검출 (11종)
각 항목: `isUse`(활성), `count`(기준건수), `exceptRegexp`(예외정규식)
| code | 대상 | code | 대상 |
|------|------|------|------|
| 10 | 주민등록번호 | 11 | 외국인주민번호 |
| 20 | 이메일 | 30 | 운전면허번호 |
| 40 | 여권번호 | 50 | 전화번호 |
| 51 | 휴대전화번호 | 60 | 사업자등록번호 |
| 70 | 법인등록번호 | 80 | 신용카드번호 |
| 85 | 계좌번호 | | |

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

### RDP 정책 (innoMark 전용)
| 필드 | 설명 | 보안 |
|------|------|------|
| isConnect / isAlwaysConnect | RDP 제어/항상허용 | 🔴 |
| connectPort / accessLimitCount / accessLimitIdleMinute | 포트/실패/유휴 | 🟠 |
| connectStartHour~connectWeek | 허용 시간/요일 | 🟠 |
| rdpClipboardUseType | **클립보드** — BOTH_ALLOW(양방향,1)/BOTH_DENY/IN_ALLOW/OUT_ALLOW | 🔴 |
| isBlockFileCopy | **RDP 파일복사 차단** | 🔴 |
| isBeforeShutdownText / beforeShutdownTextMinute | 종료 안내 | 🟡 |

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
15. isAccessControl=true이나 모든 세부(isCmd,isRegedit 등) false → 껍데기 접근제어
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

TRANSLATE_PROMPT = f"""당신은 이노티움(Innotium) 보안 솔루션 6개 제품의 정책 분석 전문가입니다.
입력된 정책 JSON을 **사람이 읽을 수 있는 자연어**로 번역하세요.

⚠ 절대 규칙:
- JSON 코드를 그대로 출력하지 마세요. 모든 필드를 자연어 문장으로 번역하세요.
- 필드명을 나열할 때도 "이 설정은 ~를 의미합니다" 형태로 설명하세요.
- 비전문가도 이해할 수 있게 기술 용어를 쉽게 풀어쓰세요.
- 비밀번호 필드 원본값은 절대 노출하지 마세요.

{POLICY_KNOWLEDGE}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 출력 형식 (반드시 준수)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 📌 정책 개요
어떤 제품의 어떤 정책인지 자동 판별. 이름, 유형, 상태, 생성일 요약.

## 🔒 보안 설정 분석

### 활성화된 보안 기능
각 기능: **기능명**(자연어) → 동작 설명 → 보안 영향도(🔴/🟠/🟡)

### 비활성화/미설정
꺼져 있는 주요 보안 기능과 위험 설명

## 🔗 연결 구성요소
ID로 참조된 템플릿, 제어스위트 등

## 📊 보안 수준 평가
상/중/하 + 근거

## ⚠️ 권고사항
누락, 위험, 개선 제안
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

CHAT_SYSTEM_PROMPT = f"""당신은 이노티움(Innotium) 보안 플랫폼 전문 어시스턴트입니다.
신입 엔지니어부터 실무 담당자까지, 자연어로 질문하면 정책 분석·조회·진단을 도와줍니다.

## 핵심 원칙
- 모든 응답은 **한국어**로 작성
- DB 조회가 필요한 경우 반드시 도구(tool)를 먼저 호출해 실제 데이터를 확인 후 답변
- 추측이나 일반론으로 답하지 말고, 실제 DB 데이터에 근거해서 답변
- 정책 분석 요청 시 analyze_policy 도구를 활용해 상세 분석 제공
- READ ONLY — 정책 변경/삭제/생성은 절대 안 내
- 도구 호출 결과가 비어 있으면 "현재 데이터 없음"으로 솔직하게 안내

## 이노티움 제품 지식
{POLICY_KNOWLEDGE}
"""

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
        return jsonify({
            "success": True,
            "result": call_claude(TRANSLATE_PROMPT, user_msg),
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
        return jsonify({"success": True, "result": call_claude(SIMULATE_PROMPT, user_msg), "feature": "simulate"})
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
        return jsonify({"success": True, "result": call_claude(DIAGNOSE_PROMPT, user_msg), "feature": "diagnose"})
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

        if not user_message:
            return jsonify({"error": "message가 필요합니다"}), 400

        # 히스토리 최대 20턴(40개 메시지)으로 truncate
        if len(history) > 40:
            history = history[-40:]

        messages = history + [{"role": "user", "content": user_message}]

        MAX_LOOPS = 5
        tool_calls_made = []

        for _ in range(MAX_LOOPS):
            response = client.messages.create(
                model=MODEL_NAME,
                max_tokens=8192,
                temperature=0.3,
                system=CHAT_SYSTEM_PROMPT,
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


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
