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


// ═══ Dashboard ═══

const PRODUCT_LABELS = {
    securezone:        'SecureZone',
    securezone_acl:    'SecureZone ACL',
    controlsuite:      'ControlSuite',
    ransomcruncher:    'RansomCruncher',
    ransomcruncher_rdp:'RC RDP',
    npouch:            'nPouch',
    npouch_origin:     'nPouch 원본보호',
    innomark:          'innoMark',
    innomark_rdp:      'IM RDP',
    lizardbackup:      'LizardBackup',
    lizardbackup_agent:'LB 에이전트',
    unified:           '통합정책',
};

async function loadDashboard() {
    const badge = document.getElementById('dbStatusBadge');
    const statsEl = document.getElementById('dashboardStats');
    const policiesEl = document.getElementById('dashboardPolicies');

    try {
        const res = await fetch('/api/dashboard');
        const data = await res.json();

        if (!data.connected) {
            badge.textContent = 'DB 연결 실패';
            badge.className = 'db-status db-status--error';
            policiesEl.innerHTML = `<div class="dash-error">DB 연결 오류: ${data.error || '알 수 없음'}</div>`;
            return;
        }

        badge.textContent = '연결됨';
        badge.className = 'db-status db-status--ok';

        // 사용자/부서
        document.getElementById('statUsers').textContent = data.users ?? '-';
        document.getElementById('statGroups').textContent = data.groups ?? '-';

        // 제품별 정책 수
        const products = data.products || {};
        policiesEl.innerHTML = '';
        for (const [key, count] of Object.entries(products)) {
            const label = PRODUCT_LABELS[key] || key;
            const card = document.createElement('div');
            card.className = 'dash-policy-card' + (count > 0 ? ' dash-policy-card--has-data' : '');
            card.innerHTML = `
                <span class="dash-policy-card__name">${label}</span>
                <span class="dash-policy-card__count">${count < 0 ? '?' : count}</span>
            `;
            policiesEl.appendChild(card);
        }
    } catch (err) {
        badge.textContent = 'DB 오프라인';
        badge.className = 'db-status db-status--error';
        policiesEl.innerHTML = `<div class="dash-error">서버 연결 실패</div>`;
    }
}


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

    // 대시보드 초기 로드
    loadDashboard();

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
    const dbSection = document.getElementById('dbSection');
    const logSection = document.getElementById('logSection');
    const inputArea = document.querySelector('.input-area');
    const btnText = document.getElementById('btnText');
    const analyzeBtn = document.getElementById('analyzeBtn');

    // Reset visibility
    querySection.style.display = 'none';
    dbSection.style.display = 'none';
    logSection.style.display = 'none';
    inputArea.style.display = 'flex';
    analyzeBtn.style.display = 'flex';

    if (currentFeature === 'simulate') {
        querySection.style.display = 'flex';
        btnText.textContent = '시뮬레이션 실행';
    } else if (currentFeature === 'translate') {
        btnText.textContent = '정책 번역';
    } else if (currentFeature === 'diagnose') {
        btnText.textContent = '정책 진단';
    } else if (currentFeature === 'db') {
        inputArea.style.display = 'none';
        dbSection.style.display = 'flex';
        analyzeBtn.style.display = 'none';
    } else if (currentFeature === 'log') {
        inputArea.style.display = 'none';
        logSection.style.display = 'flex';
        analyzeBtn.style.display = 'none';
        // Auto-load log list on first visit
        if (document.getElementById('logList').querySelector('.browser-empty')) {
            refreshLogList();
        }
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

            // Reset feedback buttons
            document.querySelectorAll('.btn-feedback').forEach(b => b.classList.remove('active'));

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


// ═══ DB Browser ═══

async function loadPolicies() {
    const product = document.getElementById('dbProductSelect').value;
    const listEl = document.getElementById('policyList');

    if (!product) {
        showToast('제품을 선택해주세요');
        return;
    }

    listEl.innerHTML = '<div class="browser-loading"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> 불러오는 중...</div>';

    try {
        const res = await fetch(`/api/policies/${product}`);
        const data = await res.json();

        if (data.error) {
            listEl.innerHTML = `<div class="browser-empty">오류: ${data.error}</div>`;
            return;
        }

        if (!data.policies || data.policies.length === 0) {
            listEl.innerHTML = '<div class="browser-empty">정책이 없습니다</div>';
            return;
        }

        listEl.innerHTML = '';
        data.policies.forEach(p => {
            const item = document.createElement('div');
            item.className = 'policy-item';
            item.dataset.id = p.id;
            item.dataset.product = product;

            const dateStr = p.updateDatetime
                ? new Date(p.updateDatetime).toLocaleDateString('ko-KR')
                : (p.createDatetime ? new Date(p.createDatetime).toLocaleDateString('ko-KR') : '');

            item.innerHTML = `
                <span class="policy-item__icon">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <ellipse cx="12" cy="5" rx="9" ry="3"/>
                        <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/>
                        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
                    </svg>
                </span>
                <span class="policy-item__name" title="${p.name || '(이름 없음)'}">${p.name || '(이름 없음)'}</span>
                <span class="policy-item__id">#${p.id}</span>
                ${dateStr ? `<span class="policy-item__date">${dateStr}</span>` : ''}
            `;
            item.addEventListener('click', () => loadPolicyDetail(product, p.id, p.name, item));
            listEl.appendChild(item);
        });

        showToast(`${data.policies.length}개 정책 조회 완료`);
    } catch (err) {
        listEl.innerHTML = `<div class="browser-empty">연결 오류: ${err.message}</div>`;
    }
}

async function loadPolicyDetail(product, id, name, itemEl) {
    // Highlight selected
    document.querySelectorAll('.policy-item').forEach(el => el.classList.remove('selected'));
    itemEl.classList.add('selected');

    showToast('정책 불러오는 중...');

    try {
        const res = await fetch(`/api/policies/${product}/${id}`);
        const data = await res.json();

        if (data.error) {
            showToast('오류: ' + data.error);
            return;
        }

        // Put JSON in the textarea and switch to translate tab
        const formatted = JSON.stringify(data, null, 2);
        document.getElementById('policyInput').value = formatted;
        document.getElementById('charCount').textContent = formatted.length + '자';

        // Switch to translate tab
        const translateTab = document.querySelector('[data-feature="translate"]');
        selectTab(translateTab);

        showToast(`"${name}" 로드 완료 — 분석 버튼을 눌러주세요`);
    } catch (err) {
        showToast('연결 오류: ' + err.message);
    }
}


// ═══ Log Browser ═══

async function refreshLogList() {
    const listEl = document.getElementById('logList');
    listEl.innerHTML = '<div class="browser-loading"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg> 불러오는 중...</div>';

    try {
        const res = await fetch('/api/logs/list');
        const data = await res.json();

        if (data.error) {
            listEl.innerHTML = `<div class="browser-empty">오류: ${data.error}</div>`;
            return;
        }

        const groups = data.groups || {};
        const hasAny = Object.values(groups).some(arr => arr && arr.length > 0);

        if (!hasAny) {
            listEl.innerHTML = '<div class="browser-empty">로그 파일이 없습니다</div>';
            return;
        }

        listEl.innerHTML = '';
        const groupLabels = {
            'catalina': 'Tomcat Catalina',
            'agent': '에이전트 로그',
            'nginx': 'Nginx',
            'policy-analyzer': 'Policy Analyzer',
            'other': '기타'
        };

        for (const [groupKey, files] of Object.entries(groups)) {
            if (!files || files.length === 0) continue;

            const groupEl = document.createElement('div');
            groupEl.className = 'log-group';
            groupEl.innerHTML = `<div class="log-group__title">${groupLabels[groupKey] || groupKey}</div>`;

            files.forEach(f => {
                const item = document.createElement('div');
                item.className = 'log-item';
                const sizeStr = f.size != null ? formatFileSize(f.size) : '';
                item.innerHTML = `
                    <span class="log-item__icon">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                            <polyline points="14 2 14 8 20 8"/>
                        </svg>
                    </span>
                    <span class="log-item__name" title="${f.path}">${f.name}</span>
                    ${sizeStr ? `<span class="log-item__size">${sizeStr}</span>` : ''}
                `;
                item.addEventListener('click', () => analyzeLog(f.path, f.name, item));
                groupEl.appendChild(item);
            });

            listEl.appendChild(groupEl);
        }

        const total = Object.values(groups).reduce((acc, arr) => acc + (arr ? arr.length : 0), 0);
        showToast(`로그 파일 ${total}개 발견`);
    } catch (err) {
        listEl.innerHTML = `<div class="browser-empty">연결 오류: ${err.message}</div>`;
    }
}

async function analyzeLog(path, name, itemEl) {
    document.querySelectorAll('.log-item').forEach(el => el.classList.remove('selected'));
    itemEl.classList.add('selected');

    const loadingState = document.getElementById('loadingState');
    const emptyState = document.getElementById('emptyState');
    const resultState = document.getElementById('resultState');
    const loadingFeature = document.getElementById('loadingFeature');

    emptyState.style.display = 'none';
    resultState.style.display = 'none';
    loadingState.style.display = 'flex';
    loadingFeature.textContent = `"${name}" 분석 중...`;

    try {
        const res = await fetch('/api/logs/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path })
        });
        const data = await res.json();

        if (data.success) {
            lastResult = data.result;
            document.getElementById('resultBadgeText').textContent = '로그 분석 완료';
            const resultContent = document.getElementById('resultContent');
            if (typeof marked !== 'undefined') {
                resultContent.innerHTML = marked.parse(data.result);
            } else {
                resultContent.innerHTML = '<pre>' + data.result + '</pre>';
            }
            document.querySelectorAll('.btn-feedback').forEach(b => b.classList.remove('active'));
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
    }
}

// ═══ Feedback ═══

async function submitFeedback(rating) {
    if (!lastResult) return;

    const policyText = document.getElementById('policyInput').value.trim();
    const goodBtn = document.querySelector('.btn-feedback--good');
    const badBtn = document.querySelector('.btn-feedback--bad');

    // Visual feedback
    goodBtn.classList.toggle('active', rating === 1);
    badBtn.classList.toggle('active', rating === -1);

    try {
        await fetch('/api/feedback', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                policy: policyText,
                result: lastResult,
                feature: currentFeature,
                rating,
                product: ''
            })
        });
        showToast(rating === 1 ? '좋은 평가 감사합니다! 학습에 활용됩니다.' : '피드백 저장됨');
    } catch {
        showToast('피드백 저장 실패');
    }
}

function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + 'B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + 'KB';
    return (bytes / (1024 * 1024)).toFixed(1) + 'MB';
}
