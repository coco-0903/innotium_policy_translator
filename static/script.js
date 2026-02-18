/* ═══════════════════════════════════════════
   Policy Analyzer — Frontend Logic
   ═══════════════════════════════════════════ */

// ── State ──
let currentFeature = 'translate';
let lastResult = '';

// ── Sample Policy (6개 제품 통합 샘플) ──
const SAMPLE_POLICY = {
    "SecureZone_에이전트정책": {
        "szAgentPolicyId": 1,
        "szAgentPolicyName": "hi",
        "szAgentPolicyType": "DEFAULT",
        "status": "CREATE",
        "secureDriveTemplateId": 0,
        "secureDriveTemplateName": "securezone policy",
        "secureDriveLetter": "C",
        "takeoutDriveLetter": "S",
        "controlSuiteId": 3,
        "controlSuiteTemplateName": "테스트",
        "isAllowDenyProcess": 0,
        "isAllowDenyProcessUse": false,
        "isBlockExecuteProcess": null,
        "isManageFolder": null,
        "isSyncFolder": null,
        "isWatchFile": null,
        "isWatchFolder": null,
        "isPrintUse": false,
        "isPrint": 0,
        "isTakeoutDriveBlock": null,
        "isShowAgentShutdownMenu": true,
        "isOfflineUse": false,
        "isLogin": false,
        "secureDriveBlockTime": 0,
        "createDatetime": "2026-02-11 11:16:53"
    },
    "SecureZone_제어스위트": {
        "csuId": 3,
        "csuName": "테스트",
        "isClipboardRestrict": false,
        "isNetwork": false,
        "isAllowExtension": true,
        "controlExtension": "",
        "isHeaderCheck": false,
        "isSignExcept": false,
        "controlSuiteProcessList": [],
        "controlSuiteWebRestrictList": []
    },
    "SecureZone_접근제어": {
        "szAccessControlPolicyId": 1,
        "szAccessControlPolicyName": "ㅅㄷㄴㅅ",
        "isAccessControl": false,
        "isCmd": false,
        "isControlPanel": false,
        "isRegedit": false,
        "isMmc": false,
        "usbControlAuth": 0,
        "pickHideDrive": "",
        "pickDenyDrive": "",
        "status": "CREATE"
    },
    "RansomCruncher_탐지정책": {
        "rcDetectPolicyId": 2,
        "rcDetectPolicyName": "teststse",
        "protectExtension": "txt",
        "behaviorDetectLevelType": "LOW",
        "isRollbackUse": false,
        "rollbackFileMaxSize": 0,
        "isBlockProcessIsolation": false,
        "isRemoveIsolatedProcess": false,
        "isSoftwareCertificate": false,
        "isMssqlRemoteBlock": false,
        "isHideTrayIcon": false,
        "isAuthorizationPassword": false,
        "status": "CREATE"
    },
    "RansomCruncher_RDP": {
        "rcRdpPolicyId": 1,
        "rcRdpPolicyName": "ㄴㅇㄹㄴㅇㄹ",
        "isConnect": false,
        "isAlwaysConnect": false,
        "connectPort": 0,
        "accessLimitCount": 0,
        "connectWeek": "",
        "status": "CREATE"
    },
    "nPouch_정책": {
        "npPolicyId": 1,
        "npPolicyName": "ㅅㄷㄴㅅ",
        "isMaxReadCount": true,
        "maxReadCount": 2,
        "isMaxReadDay": true,
        "maxReadDay": 2,
        "passwordMinDigit": 3,
        "passwordMaxDigit": 8,
        "isPasswordNumberLetter": false,
        "isPasswordSpecialLetter": false,
        "npPackageFileCreateType": "READER_ZIP_HTML",
        "isOriginProtectPolicy": true,
        "defaultNpOriginProtectPolicyId": 0,
        "status": "CREATE"
    },
    "nPouch_원본보호": {
        "npOriginProtectPolicyId": 1,
        "originProtectPolicyName": "ㅅㄷㄴㅅ",
        "csuId": 3,
        "driveLetter": "D",
        "driveLabel": "dsfsdf",
        "originProtectDriveQuota": 68645027840,
        "isWatchFileExtension": true,
        "watchFileExtension": "",
        "isAllowProcess": false,
        "isBlockProcess": false,
        "isScreenWaterMark": true,
        "screenWaterMarkText": "",
        "screenWaterMarkOpacity": 0,
        "isPrintWaterMark": true,
        "printWaterMarkText": "",
        "isSecondTakeout": false,
        "status": "CREATE"
    },
    "innoECM_에이전트정책": {
        "agentPolicyId": 1,
        "agentPolicyName": "ㄴㅇㄹㄴㅇㄹ",
        "driveLetter": "d",
        "driveLabel": "d",
        "driveMountType": "LOCAL_DISK",
        "privateFolderName": "",
        "groupFolderName": "",
        "isBackupFolderHide": false,
        "isProcessPolicy": false,
        "isProcessAllow": true,
        "agentPolicyAssignGroupCount": 0,
        "agentPolicyAssignUserCount": 0,
        "status": "CREATE"
    },
    "innoECM_저장소정책": {
        "policyId": 1,
        "policyName": "sfsaf",
        "storageQuota": 344693674082304,
        "isUnlimitedStorageQuota": false,
        "uploadExtensions": "txt",
        "uploadExtensionType": "ALLOW",
        "isUploadOverQuota": true,
        "isAgentFileCopyUse": true,
        "isAgentDuplicateLoginDeny": false,
        "isAgentAutoFileLock": false,
        "isAgentFolderFileRename": true,
        "status": "CREATE"
    },
    "LizardBackup_백업정책": {
        "lbPolicyId": 1,
        "lbPolicyName": "ㅅㄷㅅㄴ",
        "sourceFolderPath": null,
        "targetFolderPath": null,
        "isBackupRealtime": false,
        "isBackupSchedule": false,
        "isTargetProtect": false,
        "lizardBackupDataProcess": {
            "lbDataProcessType": "BACKUP",
            "isEncrypt": false,
            "isCompressBackup": false,
            "isBackupVersion": false,
            "versionKeepCount": 0
        },
        "sourceLbRemoteStorageId": 0,
        "targetLbRemoteStorageId": 0,
        "status": null
    },
    "LizardBackup_에이전트": {
        "lbAgentPolicyId": 1,
        "lbAgentPolicyName": "SETS",
        "isBackupManage": false,
        "isRecovery": false,
        "isPassword": false,
        "isWithoutPasswordRemoveProgram": false,
        "isTray": true,
        "status": "CREATE"
    },
    "LizardBackup_원격저장소": {
        "lbRemoteStorageId": 1,
        "storageName": "sdfsdf",
        "storageAddress": "sadfsadf",
        "storagePort": 55,
        "storageProtocolType": "FTP",
        "storageAccount": "safsadf",
        "storageAccountPassword": "****",
        "isPassiveMode": true,
        "storagePath": "sdfsaf"
    },
    "innoMark_정책": {
        "imPolicyId": 2,
        "imPolicyName": "ㅅㄷㄴㅅ",
        "isWatermarkTrigger": true,
        "isProcessTrigger": false,
        "isUrlTrigger": false,
        "isIpTrigger": false,
        "isCapture": null,
        "isCapturePrevent": null,
        "isInvisibleWatermark": null,
        "isInvisibleWatermarkScr": null,
        "isInvisibleWatermarkPrt": null,
        "isDynamicOpacity": null,
        "isExecuteBlockProcess": null,
        "imTemplateId": 0,
        "isTargetWatermark": false,
        "status": null
    },
    "innoMark_RDP": {
        "imRdpPolicyId": 1,
        "imRdpPolicyName": "ㅅㄷㄴㅅ",
        "isConnect": false,
        "isAlwaysConnect": true,
        "connectPort": 0,
        "accessLimitCount": 0,
        "rdpClipboardUseType": "BOTH_ALLOW",
        "isBlockFileCopy": false,
        "status": "CREATE"
    },
    "innoMark_템플릿": {
        "imTemplateId": 3,
        "imTemplateName": "ㅎㅇㅌㅎ",
        "imTemplateUseType": "DISPLAY",
        "imTemplateType": "TEXT",
        "textLetter": "ㅎㅇㅌㅎ",
        "textSize": 50,
        "textColor": "#b40431",
        "textDegree": 0,
        "waterMarkOpacity": 30,
        "splitScreenLocationType": "CENTER"
    }
};


// ═══ Initialization ═══

document.addEventListener('DOMContentLoaded', () => {
    const editor = document.getElementById('policyInput');
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');

    // Char count
    editor.addEventListener('input', () => {
        document.getElementById('charCount').textContent = editor.value.length + '자';
    });

    // Ctrl+Enter shortcut
    editor.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.key === 'Enter') {
            e.preventDefault();
            analyze();
        }
        // Tab support in editor
        if (e.key === 'Tab') {
            e.preventDefault();
            const start = editor.selectionStart;
            const end = editor.selectionEnd;
            editor.value = editor.value.substring(0, start) + '  ' + editor.value.substring(end);
            editor.selectionStart = editor.selectionEnd = start + 2;
        }
    });

    // File drag & drop
    dropZone.addEventListener('click', () => fileInput.click());
    
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('drag-over');
    });
    
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('drag-over');
    });
    
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('drag-over');
        const files = Array.from(e.dataTransfer.files);
        if (files.length > 0) readMultipleFiles(files);
    });

    fileInput.addEventListener('change', (e) => {
        const files = Array.from(e.target.files);
        if (files.length > 0) readMultipleFiles(files);
        fileInput.value = '';  // 같은 파일 재업로드 가능하게
    });

    // Configure marked
    if (typeof marked !== 'undefined') {
        marked.setOptions({
            breaks: true,
            gfm: true,
        });
    }
});


// ═══ File Reading — 복수 파일 누적 지원 ═══

let loadedFileCount = 0;  // 누적 파일 수 추적

function readMultipleFiles(files) {
    let completed = 0;
    const contents = [];

    files.forEach((file, idx) => {
        const reader = new FileReader();
        reader.onload = (e) => {
            contents[idx] = { name: file.name, text: e.target.result };
            completed++;

            if (completed === files.length) {
                // 모든 파일 읽기 완료 → 누적 추가
                appendPolicies(contents);
            }
        };
        reader.readAsText(file);
    });
}

function appendPolicies(fileContents) {
    const editor = document.getElementById('policyInput');
    const existing = editor.value.trim();
    const names = [];

    let newContent = '';
    for (const fc of fileContents) {
        const text = fc.text.trim();
        if (!text) continue;
        names.push(fc.name);

        if (newContent) {
            newContent += '\n\n';
        }
        newContent += text;
    }

    // 기존 내용이 있으면 누적 (구분자 추가)
    if (existing) {
        editor.value = existing + '\n\n' + newContent;
        loadedFileCount += names.length;
    } else {
        editor.value = newContent;
        loadedFileCount = names.length;
    }

    document.getElementById('charCount').textContent = editor.value.length + '자';
    updatePolicyBadge();
    showToast(`파일 추가 완료: ${names.join(', ')} (누적 ${loadedFileCount}개)`);
}

function updatePolicyBadge() {
    const badge = document.getElementById('policyBadge');
    if (loadedFileCount > 0) {
        badge.textContent = `📁 ${loadedFileCount}개 파일 로드됨`;
        badge.style.display = 'inline';
    } else {
        badge.style.display = 'none';
    }
}


// ═══ Tab Selection ═══

function selectTab(el) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    el.classList.add('active');
    currentFeature = el.dataset.feature;

    const querySection = document.getElementById('querySection');
    const btnText = document.getElementById('btnText');

    if (currentFeature === 'simulate') {
        querySection.style.display = 'flex';
        btnText.textContent = '시뮬레이션 실행';
    } else if (currentFeature === 'translate') {
        querySection.style.display = 'none';
        btnText.textContent = '정책 번역';
    } else if (currentFeature === 'diagnose') {
        querySection.style.display = 'none';
        btnText.textContent = '정책 진단';
    }
}


// ═══ Sample Policy ═══

function loadSamplePolicy() {
    const formatted = JSON.stringify(SAMPLE_POLICY, null, 2);
    document.getElementById('policyInput').value = formatted;
    document.getElementById('charCount').textContent = formatted.length + '자';
    showToast('6개 제품 통합 샘플 정책 로드 완료');
}


// ═══ Utilities ═══

function formatJSON() {
    const editor = document.getElementById('policyInput');
    try {
        const parsed = JSON.parse(editor.value);
        editor.value = JSON.stringify(parsed, null, 2);
        showToast('JSON 포맷팅 완료');
    } catch (e) {
        showToast('로그 형식 입력 — 포맷팅 없이 그대로 분석됩니다');
    }
}

function clearInput() {
    document.getElementById('policyInput').value = '';
    document.getElementById('charCount').textContent = '0자';
    document.getElementById('emptyState').style.display = 'flex';
    document.getElementById('resultState').style.display = 'none';
    document.getElementById('loadingState').style.display = 'none';
    loadedFileCount = 0;
    updatePolicyBadge();
}

function copyResult() {
    if (lastResult) {
        navigator.clipboard.writeText(lastResult).then(() => {
            showToast('분석 결과 복사 완료');
        });
    }
}

function showToast(message) {
    const existing = document.querySelector('.toast');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), 2500);
}


// ═══ Main Analyze Function ═══

async function analyze() {
    const policyText = document.getElementById('policyInput').value.trim();
    
    if (!policyText) {
        showToast('정책 JSON을 입력해주세요');
        return;
    }

    // JSON 검증 제거 — parser.py가 서버에서 알아서 처리
    // (깨끗한 JSON, 더러운 로그, 혼합 입력 모두 지원)

    const btn = document.getElementById('analyzeBtn');
    const loadingState = document.getElementById('loadingState');
    const emptyState = document.getElementById('emptyState');
    const resultState = document.getElementById('resultState');
    const loadingFeature = document.getElementById('loadingFeature');

    // Loading state
    btn.disabled = true;
    emptyState.style.display = 'none';
    resultState.style.display = 'none';
    loadingState.style.display = 'flex';

    const featureLabels = {
        translate: '정책 → 자연어 번역 중...',
        simulate: '시뮬레이션 분석 중...',
        diagnose: '정책 건강도 진단 중...'
    };
    loadingFeature.textContent = featureLabels[currentFeature];

    try {
        let body = { policy: policyText };
        let endpoint = `/api/${currentFeature}`;

        if (currentFeature === 'simulate') {
            const query = document.getElementById('queryInput').value.trim();
            if (!query) {
                showToast('시뮬레이션 질의를 입력해주세요');
                btn.disabled = false;
                loadingState.style.display = 'none';
                emptyState.style.display = 'flex';
                return;
            }
            body.query = query;
        }

        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        const data = await response.json();

        if (data.success) {
            lastResult = data.result;

            // Update badge
            const badgeText = document.getElementById('resultBadgeText');
            const badgeLabels = {
                translate: '번역 완료',
                simulate: '시뮬레이션 완료',
                diagnose: '진단 완료'
            };
            badgeText.textContent = badgeLabels[currentFeature];

            // Render markdown
            const resultContent = document.getElementById('resultContent');
            if (typeof marked !== 'undefined') {
                resultContent.innerHTML = marked.parse(data.result);
            } else {
                resultContent.innerHTML = '<pre>' + data.result + '</pre>';
            }

            loadingState.style.display = 'none';
            resultState.style.display = 'flex';
        } else {
            showToast('분석 실패: ' + (data.error || '알 수 없는 오류'));
            loadingState.style.display = 'none';
            emptyState.style.display = 'flex';
        }
    } catch (err) {
        showToast('서버 연결 실패: ' + err.message);
        loadingState.style.display = 'none';
        emptyState.style.display = 'flex';
    } finally {
        btn.disabled = false;
    }
}
