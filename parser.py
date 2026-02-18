"""
╔══════════════════════════════════════════════════════════════╗
║  parser.py — 비정형 로그 전처리 엔진                          ║
║  더러운 에이전트 로그 → 깨끗한 정책 JSON 추출                   ║
║  6개 제품 자동 판별 + 중복 제거 + 목록 압축                     ║
╚══════════════════════════════════════════════════════════════╝
"""

import re
import json
from collections import defaultdict


# ═══════════════════════════════════════════════════
# 제품 자동 판별 시그니처
# ═══════════════════════════════════════════════════
PRODUCT_SIGNATURES = {
    "SecureZone": {
        "log_keywords": [
            "secureDrivePolicy", "accCtlAgentPolicy", "controlSuite",
            "szAgent", "itSecz", "seczPolicy", "secureDrive",
            "takeoutDrive", "manageFolder", "watchFile"
        ],
        "json_keys": [
            "szAgentPolicyId", "szAgentPolicyName", "szAccessControlPolicyId",
            "secureDriveLetter", "controlSuiteTemplateId", "csuId", "csuName",
            "isTakeoutDriveBlock", "isClipboardRestrict", "usbControlAuth",
            "isAccessControl", "isCmd", "isRegedit", "pickDenyDrive",
            "secureDriveBlockTime", "takeoutDriveLetter", "controlExtension",
            "szTemplateType", "isBlockExecuteProcess", "isAllowDenyProcess"
        ]
    },
    "RansomCruncher": {
        "log_keywords": [
            "rcDetectPolicy", "ransomCruncher", "rcRdpPolicy",
            "rollback", "ransomDetect", "rcProcess"
        ],
        "json_keys": [
            "rcDetectPolicyId", "rcDetectPolicyName", "protectExtension",
            "behaviorDetectLevelType", "isRollbackUse", "rollbackFileMaxSize",
            "isBlockProcessIsolation", "isSoftwareCertificate",
            "isMssqlRemoteBlock", "rcRdpPolicyId", "rcProcessType",
            "resRansomCruncherDetectPolicy"
        ]
    },
    "nPouch": {
        "log_keywords": [
            "npouchPolicy", "originProtect", "npouch",
            "npPackage", "npOriginProtect", "privacyExtract"
        ],
        "json_keys": [
            "npPolicyId", "npPolicyName", "npOriginProtectPolicyId",
            "isMaxReadCount", "maxReadCount", "isMaxReadDay",
            "passwordMinDigit", "npPackageFileCreateType",
            "isOriginProtectPolicy", "defaultNpOriginProtectPolicyId",
            "originProtectPolicyName", "originProtectDriveQuota",
            "isScreenWaterMark", "isSecondTakeout", "isPrintWaterMark",
            "resNpouchOriginProtectPolicy"
        ]
    },
    "innoECM": {
        "log_keywords": [
            "ecmAgent", "ecmStorage", "ecmPolicy",
            "storagePolicy", "agentPolicy", "innoECM"
        ],
        "json_keys": [
            "agentPolicyId", "agentPolicyName", "driveMountType",
            "privateFolderName", "groupFolderName", "backupFolderName",
            "sharedFolderName", "isBackupFolderHide", "isProcessPolicy",
            "storageQuota", "isUnlimitedStorageQuota", "isUploadOverQuota",
            "uploadExtensionType", "isAgentDuplicateLoginDeny",
            "isAgentAutoFileLock", "isAgentFileCopyUse"
        ]
    },
    "LizardBackup": {
        "log_keywords": [
            "lizardBackup", "lbPolicy", "lbAgent",
            "remoteStorage", "lbRemoteStorage", "lbBackup"
        ],
        "json_keys": [
            "lbPolicyId", "lbPolicyName", "lbAgentPolicyId",
            "sourceFolderPath", "targetFolderPath", "isBackupRealtime",
            "isBackupSchedule", "lizardBackupDataProcess",
            "lbRemoteStorageId", "storageProtocolType",
            "storageAccountPassword", "isEncrypt", "isRecovery",
            "lbDataProcessType", "isBackupVersion", "isTargetProtect"
        ]
    },
    "innoMark": {
        "log_keywords": [
            "innoMark", "imPolicy", "imTemplate",
            "watermark", "capturePrevent", "imRdpPolicy"
        ],
        "json_keys": [
            "imPolicyId", "imPolicyName", "isWatermarkTrigger",
            "isProcessTrigger", "isUrlTrigger", "isCapturePrevent",
            "isInvisibleWatermark", "isDynamicOpacity", "imTemplateId",
            "isTargetWatermark", "isExecuteBlockProcess",
            "rdpClipboardUseType", "isBlockFileCopy",
            "imTemplateUseType", "imTemplateType", "textLetter",
            "waterMarkOpacity", "isAlwaysUseCapturePrevent",
            "imRdpPolicyId", "isAlwaysConnect"
        ]
    }
}

# 압축 대상 목록형 필드 (길이가 길어지는 배열들)
COMPRESSIBLE_FIELDS = [
    "exceptProcessList", "controlSuiteProcessList",
    "controlSuiteProcessTagList", "controlSuiteWebRestrictList",
    "csuProcessList", "csuWebRestrictList",
    "resRansomCruncherDetectExceptList",
    "resNpouchOriginProtectWatchFolderList",
    "resNpouchOriginProtectProcessList",
    "uploadExtensionList",
    "imProcessTriggerList", "imUrlTriggerList",
    "imIpTriggerList", "imRegistTriggerList"
]

# 민감 필드 (마스킹 처리)
SENSITIVE_FIELDS = [
    "authorizationPassword", "storageAccountPassword",
    "cryptoKey", "password"
]


# ═══════════════════════════════════════════════════
# 핵심 함수: 입력 타입 자동 감지
# ═══════════════════════════════════════════════════
def detect_input_type(raw_input):
    """입력이 깨끗한 JSON인지 더러운 로그인지 자동 판별"""
    text = raw_input.strip()

    # Case 1: 깨끗한 JSON 객체 (단일)
    if text.startswith('{') and text.endswith('}'):
        try:
            json.loads(text)
            return "clean_json"
        except json.JSONDecodeError:
            # 여러 JSON이 붙어있을 수 있음 {...}{...} 또는 {...}\n{...}
            if _count_top_level_jsons(text) > 1:
                return "multi_json"

    # Case 2: 깨끗한 JSON 배열
    if text.startswith('[') and text.endswith(']'):
        try:
            json.loads(text)
            return "clean_json_array"
        except json.JSONDecodeError:
            pass

    # Case 2.5: 구분자로 나뉜 복수 JSON  ─────  또는 ===== 등
    if re.search(r'\}\s*[\n─=\-]{2,}\s*\{', text):
        return "multi_json"

    # Case 2.6: 줄바꿈으로 나뉜 복수 JSON
    if re.search(r'\}\s*\n\s*\{', text):
        if _count_top_level_jsons(text) > 1:
            return "multi_json"

    # Case 3: 로그 (타임스탬프 패턴 존재)
    if re.search(r'\d{6}\s+\d{2}:\d{2}:\d{2}', text):
        return "agent_log"

    # Case 4: Policy= 패턴이 있는 로그
    if 'Policy=' in text or 'policy=' in text:
        return "policy_log"

    # Case 5: JSON이 텍스트 사이에 섞여있음
    if re.search(r'\{[^{}]*"[a-zA-Z]+"[^{}]*:', text):
        return "mixed_content"

    return "unknown"


def _count_top_level_jsons(text):
    """최상위 레벨 JSON 객체 수를 센다"""
    count = 0
    depth = 0
    for ch in text:
        if ch == '{':
            if depth == 0:
                count += 1
            depth += 1
        elif ch == '}':
            depth -= 1
    return count


def extract_multiple_jsons(text):
    """연속된 여러 JSON 객체를 분리 추출"""
    jsons = []
    text = text.strip()

    # 구분자 제거 (─── , ===, --- 등)
    text = re.sub(r'[\n\r]\s*[─=\-]{2,}\s*[\n\r]', '\n', text)

    # 중괄호 균형으로 분리
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start is not None:
                json_str = text[start:i+1]
                try:
                    parsed = json.loads(json_str)
                    jsons.append(parsed)
                except json.JSONDecodeError:
                    pass
                start = None

    return jsons


# ═══════════════════════════════════════════════════
# Step 1: 로그에서 JSON 추출
# ═══════════════════════════════════════════════════
def extract_json_from_log(raw_text):
    """더러운 로그에서 모든 JSON 객체 추출"""
    extracted = []
    errors = []
    sign_policies = []

    lines = raw_text.split('\n')

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue

        # ── 패턴 1: Policy={...} 형태 ──
        policy_matches = re.finditer(r'Policy=(\{.+)', line)
        for match in policy_matches:
            json_str = match.group(1)
            parsed = _safe_parse_json(json_str)
            if parsed:
                # 로그 컨텍스트 (어떤 정책인지 힌트)
                context = line[:line.find('Policy=')].strip().rstrip(',')
                extracted.append({
                    "_source": "log",
                    "_line": line_num,
                    "_context": context,
                    "_data": parsed
                })

        # ── 패턴 2: "policy":{...} 가 포함된 라인 (래퍼 안) ──
        if '"policy"' in line and 'Policy=' not in line:
            inner_matches = re.finditer(r'"policy"\s*:\s*(\{.+?\})\s*[,}]', line)
            for match in inner_matches:
                parsed = _safe_parse_json(match.group(1))
                if parsed:
                    extracted.append({
                        "_source": "log_inner",
                        "_line": line_num,
                        "_context": "embedded_policy",
                        "_data": parsed
                    })

        # ── 패턴 3: 독립 JSON 객체 (줄 전체가 JSON) ──
        if line.startswith('{'):
            parsed = _safe_parse_json(line)
            if parsed:
                extracted.append({
                    "_source": "standalone",
                    "_line": line_num,
                    "_context": "",
                    "_data": parsed
                })

        # ── 패턴 4: Sign Except Policy 라인 ──
        sign_match = re.match(
            r'.*Sign Except Policy,\s*sign=(.+?),\s*type=(\d+)',
            line
        )
        if sign_match:
            sign_policies.append({
                "sign": sign_match.group(1).strip(),
                "type": int(sign_match.group(2))
            })

        # ── 패턴 5: [itError] 에러 메시지 ──
        error_match = re.match(r'.*\[itError\]:(.+)', line)
        if error_match:
            errors.append({
                "_line": line_num,
                "_message": error_match.group(1).strip()
            })

    return extracted, sign_policies, errors


def _safe_parse_json(json_str):
    """JSON 파싱 시도 — 깨진 JSON도 최대한 복구"""
    # 시도 1: 그대로 파싱
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        pass

    # 시도 2: 중괄호 균형 맞추기 (로그에서 잘린 경우)
    try:
        depth = 0
        end_idx = 0
        for i, ch in enumerate(json_str):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            if depth == 0 and i > 0:
                end_idx = i + 1
                break
        if end_idx > 0:
            return json.loads(json_str[:end_idx])
    except (json.JSONDecodeError, IndexError):
        pass

    # 시도 3: 후행 쓰레기 제거
    try:
        # 마지막 } 위치 찾기
        last_brace = json_str.rfind('}')
        if last_brace > 0:
            return json.loads(json_str[:last_brace + 1])
    except json.JSONDecodeError:
        pass

    return None


# ═══════════════════════════════════════════════════
# Step 2: 제품 자동 판별
# ═══════════════════════════════════════════════════
def detect_product(entry):
    """추출된 정책 데이터에서 제품 자동 판별"""
    data = entry.get("_data", {})
    context = entry.get("_context", "")

    scores = defaultdict(int)

    # JSON 키 기반 매칭
    all_keys = _get_all_keys(data)
    for product, sigs in PRODUCT_SIGNATURES.items():
        for key in sigs["json_keys"]:
            if key in all_keys:
                scores[product] += 3  # JSON 키 매칭은 가중치 높음

    # 로그 컨텍스트 키워드 매칭
    context_lower = context.lower()
    data_str = json.dumps(data, ensure_ascii=False).lower()
    for product, sigs in PRODUCT_SIGNATURES.items():
        for keyword in sigs["log_keywords"]:
            if keyword.lower() in context_lower:
                scores[product] += 5  # 컨텍스트 매칭은 가중치 최고
            if keyword.lower() in data_str:
                scores[product] += 1

    if not scores:
        return "Unknown"

    # 최고 점수 제품 반환
    best = max(scores, key=scores.get)
    return best if scores[best] >= 3 else "Unknown"


def _get_all_keys(obj, prefix=""):
    """중첩 JSON의 모든 키를 평탄화하여 반환"""
    keys = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(k)
            keys.update(_get_all_keys(v, f"{prefix}{k}."))
    elif isinstance(obj, list):
        for item in obj:
            keys.update(_get_all_keys(item, prefix))
    return keys


# ═══════════════════════════════════════════════════
# Step 3: 래퍼 언래핑 + 실제 정책 추출
# ═══════════════════════════════════════════════════
def unwrap_policy(data):
    """래퍼 구조에서 실제 정책 객체 추출"""
    # 패턴 1: {"id":"...", "time":"...", "policy":{실제데이터}}
    if "policy" in data and isinstance(data["policy"], dict):
        inner = data["policy"]
        # 메타데이터 보존
        if "id" in data:
            inner["_wrapper_id"] = data["id"]
        if "time" in data:
            inner["_wrapper_time"] = data["time"]
        return inner

    # 패턴 2: RansomCruncher 래퍼
    if "resRansomCruncherDetectPolicy" in data:
        inner = data["resRansomCruncherDetectPolicy"]
        if isinstance(inner, list) and len(inner) > 0:
            return inner[0] if isinstance(inner[0], dict) else data
        elif isinstance(inner, dict):
            return inner

    # 패턴 3: nPouch 래퍼
    if "resNpouchOriginProtectPolicy" in data:
        inner = data["resNpouchOriginProtectPolicy"]
        if isinstance(inner, list) and len(inner) > 0:
            return inner[0] if isinstance(inner[0], dict) else data
        elif isinstance(inner, dict):
            return inner

    return data


# ═══════════════════════════════════════════════════
# Step 4: 중복 제거
# ═══════════════════════════════════════════════════
def deduplicate(entries):
    """같은 정책 ID의 중복 제거 — 마지막(최신) 것만 유지"""
    seen = {}

    for entry in entries:
        data = entry["_data"]
        product = entry.get("_product", "Unknown")

        # 정책 ID 추출 (제품별로 다른 키 이름)
        policy_id = None
        for key in data:
            if key.endswith("PolicyId") or key.endswith("TemplateId"):
                policy_id = f"{product}:{key}:{data[key]}"
                break

        if policy_id is None:
            # ID가 없으면 컨텍스트 기반으로 키 생성
            policy_id = f"{product}:{entry.get('_context', '')}:{entry['_line']}"

        # 나중에 나온 것이 최신 (덮어쓰기)
        seen[policy_id] = entry

    return list(seen.values())


# ═══════════════════════════════════════════════════
# Step 5: 스마트 압축 + 민감정보 마스킹
# ═══════════════════════════════════════════════════
def compress_and_mask(data):
    """목록 항목을 한 줄 형태로 압축 (항목 수는 유지!) + 민감 필드 마스킹"""
    if isinstance(data, dict):
        result = {}
        for key, value in data.items():
            # 민감 필드 마스킹
            if key in SENSITIVE_FIELDS:
                if value and str(value).strip():
                    result[key] = "***설정됨***"
                else:
                    result[key] = "미설정"
                continue

            # 목록 → 항목 수는 전부 유지, 각 항목만 한 줄로 압축
            if key in COMPRESSIBLE_FIELDS and isinstance(value, list):
                result[key] = _compact_list(key, value)
                continue

            # 재귀 처리
            result[key] = compress_and_mask(value)
        return result

    elif isinstance(data, list):
        return [compress_and_mask(item) for item in data]

    return data


def _compact_list(key, items):
    """목록 전체를 유지하되, 각 항목을 한 줄 문자열로 압축"""
    if not items:
        return []

    compacted = []

    for item in items:
        if not isinstance(item, dict):
            compacted.append(item)
            continue

        # ── 프로세스 목록 (exceptProcessList 등) ──
        if "processName" in item:
            name = item.get("processName", "?")
            sign = item.get("signs", item.get("sign", ""))
            sha2 = item.get("sha2s", item.get("sha2", ""))
            parts = [name]
            if sign:
                parts.append(f"서명:{sign}")
            if sha2:
                parts.append("SHA2:있음")
            if item.get("isPassUncon"):
                parts.append("무조건허용")
            compacted.append(" | ".join(parts))
            continue

        # ── 웹 제한 목록 ──
        if "url" in item or "address" in item:
            url = item.get("url", item.get("address", "?"))
            compacted.append(url)
            continue

        # ── 확장자 목록 ──
        if "extension" in item:
            compacted.append(item.get("extension", "?"))
            continue

        # ── 트리거 목록 (innoMark) ──
        if "triggerValue" in item or "processName" in item:
            val = item.get("triggerValue", item.get("processName", "?"))
            compacted.append(val)
            continue

        # ── 일반: 키=값 한줄로 ──
        parts = []
        for k, v in item.items():
            if k.startswith("_"):
                continue
            if v is None or v == "" or v == []:
                continue
            # 중첩 객체는 스킵
            if isinstance(v, (dict, list)):
                continue
            parts.append(f"{k}={v}")
        compacted.append(" | ".join(parts) if parts else str(item))

    return {
        "_총개수": len(items),
        "_전체목록": compacted
    }


def _summarize_list(key, items):
    """목록을 한 줄 요약으로 압축 (디지털서명 등 보조용)"""
    if not items:
        return "비어있음"

    if key == "exceptProcessList":
        names = []
        for item in items:
            if isinstance(item, dict):
                name = item.get("processName", "?")
                if name != "all":
                    names.append(name)
        named = [n for n in names if n != "?"]
        all_count = sum(1 for item in items
                       if isinstance(item, dict) and item.get("processName") == "all")
        parts = []
        if named:
            parts.append(f"개별 프로세스 {len(named)}개")
        if all_count:
            parts.append(f"서명 기반 전체허용 {all_count}개")
        return ", ".join(parts) if parts else f"항목 {len(items)}개"

    # 기본 요약
    return f"항목 {len(items)}개"


# ═══════════════════════════════════════════════════
# Step 6: 최종 출력 — AI에 보낼 구조화된 요약
# ═══════════════════════════════════════════════════
def generate_ai_input(entries, sign_policies, errors):
    """전처리 완료된 데이터를 AI가 소화할 수 있는 포맷으로 변환"""
    output = {}

    # 제품별 그룹핑
    by_product = defaultdict(list)
    for entry in entries:
        product = entry.get("_product", "Unknown")
        by_product[product].append(entry)

    # 제품별 정책 출력
    for product, product_entries in by_product.items():
        product_data = {}
        for i, entry in enumerate(product_entries):
            context = entry.get("_context", "")
            # 정책 이름 추출
            data = entry["_data"]
            policy_name = _extract_policy_name(data)
            key = policy_name or context or f"정책_{i+1}"
            product_data[key] = data
        output[product] = product_data

    # 디지털서명 예외 (있으면)
    if sign_policies:
        signs = [sp["sign"] for sp in sign_policies]
        output["_디지털서명_예외"] = {
            "총개수": len(signs),
            "목록": signs[:10],  # 최대 10개만
            "생략": max(0, len(signs) - 10)
        }

    # 에러 메시지 (있으면)
    if errors:
        output["_로그_에러"] = [e["_message"] for e in errors[:10]]

    return output


def _extract_policy_name(data):
    """정책 데이터에서 이름 추출"""
    name_keys = [
        "szAgentPolicyName", "szAccessControlPolicyName",
        "rcDetectPolicyName", "rcRdpPolicyName",
        "npPolicyName", "originProtectPolicyName",
        "agentPolicyName", "policyName",
        "lbPolicyName", "lbAgentPolicyName", "storageName",
        "imPolicyName", "imTemplateName", "imRdpPolicyName",
        "csuName", "procPolicyName"
    ]
    for key in name_keys:
        if key in data and data[key]:
            return str(data[key])
    return None


# ═══════════════════════════════════════════════════
# 메인 인터페이스 — app.py에서 호출
# ═══════════════════════════════════════════════════
def parse_input(raw_input):
    """
    메인 함수: 어떤 형태의 입력이든 받아서 AI에 보낼 깨끗한 데이터 반환

    Returns:
        dict: {
            "input_type": str,           # 입력 타입
            "policies": dict,            # 제품별 정책 데이터
            "policy_count": int,         # 추출된 정책 수
            "products_found": list,      # 발견된 제품 목록
            "errors": list,              # 로그 에러 (있으면)
            "clean_json": str,           # AI에 보낼 최종 JSON 문자열
        }
    """
    input_type = detect_input_type(raw_input)

    # ── 복수 JSON이 연결된 경우 ({...}{...} 또는 {...}\n{...}) ──
    if input_type == "multi_json":
        jsons = extract_multiple_jsons(raw_input)
        if jsons:
            entries = []
            for i, data in enumerate(jsons):
                unwrapped = unwrap_policy(data)
                masked = compress_and_mask(unwrapped)
                entry = {
                    "_source": "multi_json",
                    "_line": i,
                    "_context": f"정책_{i+1}",
                    "_data": masked
                }
                entry["_product"] = detect_product(entry)
                entries.append(entry)

            unique = deduplicate(entries)
            result_data = generate_ai_input(unique, [], [])
            products = list(set(e["_product"] for e in unique))

            clean_json = json.dumps(result_data, indent=2, ensure_ascii=False)
            MAX_CHARS = 30000
            if len(clean_json) > MAX_CHARS:
                clean_json = _emergency_compress(result_data, MAX_CHARS)

            return {
                "input_type": "multi_json",
                "policies": result_data,
                "policy_count": len(unique),
                "products_found": products,
                "errors": [],
                "clean_json": clean_json
            }

    # ── 깨끗한 JSON이면 최소 전처리만 ──
    if input_type in ("clean_json", "clean_json_array"):
        try:
            data = json.loads(raw_input)
            if isinstance(data, list):
                # 배열이면 각 항목 처리
                entries = []
                for i, item in enumerate(data):
                    if isinstance(item, dict):
                        unwrapped = unwrap_policy(item)
                        masked = compress_and_mask(unwrapped)
                        entry = {
                            "_source": "clean_json",
                            "_line": i,
                            "_context": "",
                            "_data": masked
                        }
                        entry["_product"] = detect_product(entry)
                        entries.append(entry)
            else:
                unwrapped = unwrap_policy(data)
                masked = compress_and_mask(unwrapped)
                entry = {
                    "_source": "clean_json",
                    "_line": 0,
                    "_context": "",
                    "_data": masked
                }
                entry["_product"] = detect_product(entry)
                entries = [entry]

            result_data = generate_ai_input(entries, [], [])
            products = list(set(e["_product"] for e in entries))

            return {
                "input_type": input_type,
                "policies": result_data,
                "policy_count": len(entries),
                "products_found": products,
                "errors": [],
                "clean_json": json.dumps(result_data, indent=2, ensure_ascii=False)
            }
        except Exception as e:
            return {
                "input_type": "error",
                "policies": {},
                "policy_count": 0,
                "products_found": [],
                "errors": [str(e)],
                "clean_json": raw_input
            }

    # ── 더러운 로그면 전체 파이프라인 실행 ──
    # Step 1: JSON 추출
    extracted, sign_policies, errors = extract_json_from_log(raw_input)

    if not extracted and not sign_policies:
        # JSON을 하나도 못 찾았으면 원본 그대로 반환
        return {
            "input_type": "no_json_found",
            "policies": {},
            "policy_count": 0,
            "products_found": [],
            "errors": ["로그에서 정책 JSON을 찾지 못했습니다."],
            "clean_json": raw_input
        }

    # Step 2: 래퍼 언래핑
    for entry in extracted:
        entry["_data"] = unwrap_policy(entry["_data"])

    # Step 3: 제품 판별
    for entry in extracted:
        entry["_product"] = detect_product(entry)

    # Step 4: 중복 제거
    unique = deduplicate(extracted)

    # Step 5: 압축 + 마스킹
    for entry in unique:
        entry["_data"] = compress_and_mask(entry["_data"])

    # Step 6: AI 입력 생성
    result_data = generate_ai_input(unique, sign_policies, errors)
    products = list(set(e["_product"] for e in unique))

    clean_json = json.dumps(result_data, indent=2, ensure_ascii=False)

    # 토큰 제한 체크 (대략 1글자 = 1토큰 기준, 30000자 제한)
    MAX_CHARS = 30000
    if len(clean_json) > MAX_CHARS:
        # 너무 크면 추가 압축
        clean_json = _emergency_compress(result_data, MAX_CHARS)

    return {
        "input_type": input_type,
        "policies": result_data,
        "policy_count": len(unique),
        "products_found": products,
        "errors": [e["_message"] for e in errors] if errors else [],
        "clean_json": clean_json
    }


def _emergency_compress(data, max_chars):
    """비상 압축 — 토큰 한계 초과 시"""
    # 1차: indent 제거
    compact = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
    if len(compact) <= max_chars:
        return compact

    # 2차: 배열 항목 더 줄이기
    if isinstance(data, dict):
        for key in data:
            if isinstance(data[key], dict):
                for inner_key in data[key]:
                    val = data[key][inner_key]
                    if isinstance(val, list) and len(val) > 3:
                        data[key][inner_key] = val[:3] + [f"... 외 {len(val)-3}개"]
                    elif isinstance(val, dict):
                        for k, v in val.items():
                            if isinstance(v, list) and len(v) > 3:
                                val[k] = v[:3] + [f"... 외 {len(v)-3}개"]

    compact = json.dumps(data, ensure_ascii=False, indent=1)
    if len(compact) > max_chars:
        compact = compact[:max_chars] + "\n... (토큰 제한으로 일부 생략)"

    return compact


# ═══════════════════════════════════════════════════
# 유틸리티: 입력 통계 요약 (디버그/UI용)
# ═══════════════════════════════════════════════════
def get_input_stats(raw_input):
    """입력 텍스트의 간단한 통계"""
    lines = raw_input.split('\n')
    json_count = sum(1 for line in lines if 'Policy=' in line or line.strip().startswith('{'))
    error_count = sum(1 for line in lines if '[itError]' in line)

    return {
        "total_lines": len(lines),
        "total_chars": len(raw_input),
        "estimated_json_lines": json_count,
        "error_lines": error_count,
        "input_type": detect_input_type(raw_input)
    }


# ═══════════════════════════════════════════════════
# 테스트
# ═══════════════════════════════════════════════════
if __name__ == "__main__":
    # 테스트: 더러운 로그
    test_log = """260107 10:53:48:145 : [itError]:itProcFldRestrictPolicy::add, This process added aready. name=pycharm64.exe
260107 10:53:48:146 : Sign Except Policy, sign=microsoft windows publisher, type=0
260107 10:53:48:146 : Sign Except Policy, sign=ahnlab, inc., type=0
260107 10:53:48:146 : Sign Except Policy, sign=innotium,inc, type=0
260107 10:53:48:146 : accCtlAgentPolicyOff, Policy={"id":"1;","time":"1766398060;","policy":{"szAccessControlPolicyId":1,"szAccessControlPolicyName":"접근제어정책","pickHideDrive":"","pickDenyDrive":"","usbControlAuth":0,"isAccessControl":false,"isCmd":true,"isRegedit":true}}
260107 10:53:48:178 : secureDrivePolicy, Policy={"procPolicyName":"0_기본","driveLetter":"p","driveLabel":"보안드라이브","maxCapacity":30720,"isProcessPolicy":true,"isOnlyAccProcess":true,"isDefaultEncrypt":true,"cryptoKey":"MzyNo9mtlUq8pQnH","cryptoAlg":1}"""

    print("=" * 60)
    print("테스트: 더러운 로그 파싱")
    print("=" * 60)

    result = parse_input(test_log)

    print(f"입력 타입: {result['input_type']}")
    print(f"추출 정책 수: {result['policy_count']}")
    print(f"발견 제품: {result['products_found']}")
    print(f"에러: {result['errors']}")
    print(f"\n정제된 JSON ({len(result['clean_json'])}자):")
    print(result['clean_json'])
