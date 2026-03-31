#!/usr/bin/env python3
"""
patch_main.py — 매니저 서버 main.html에 Policy Analyzer 바로가기 버튼 자동 삽입
사용법:
  python3 /app/policy-analyzer/patch_main.py

패치 대상:
  /project/apiFront/manager/main.html
  /project/apiFront/user/main.html  (있는 경우)

각 파일의 </body> 직전에 고정(fixed) 플로팅 버튼 삽입.
이미 패치된 경우 중복 삽입 없이 갱신(기존 버튼 교체).
백업: .bak 파일 생성
"""

import os
import shutil
import sys

POLICY_ANALYZER_URL = "http://172.30.1.44:40010"

BUTTON_HTML = """\
<!-- policy-analyzer-fab: 자동 패치 버튼 (patch_main.py) -->
<style>
#policy-analyzer-fab {
    position: fixed;
    bottom: 28px;
    right: 28px;
    z-index: 99999;
    display: flex;
    align-items: center;
    gap: 8px;
    background: linear-gradient(135deg, #1e40af, #3b82f6);
    color: #fff;
    border: none;
    border-radius: 50px;
    padding: 10px 18px 10px 14px;
    font-size: 13px;
    font-weight: 600;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    cursor: pointer;
    box-shadow: 0 4px 16px rgba(59,130,246,0.5);
    text-decoration: none;
    transition: transform 0.15s, box-shadow 0.15s;
    letter-spacing: -0.2px;
}
#policy-analyzer-fab:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 22px rgba(59,130,246,0.65);
    color: #fff;
}
</style>
<a id="policy-analyzer-fab" href="{url}" target="_blank">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
    Policy Analyzer
</a>
<!-- /policy-analyzer-fab -->"""

TARGETS = [
    "/project/apiFront/manager/main.html",
    "/project/apiFront/user/main.html",
]


def patch_file(filepath: str, url: str) -> bool:
    if not os.path.isfile(filepath):
        print(f"[SKIP] 파일 없음: {filepath}")
        return False

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # 이미 패치됐으면 기존 버튼 블록 제거 후 재삽입 (갱신)
    start_marker = "<!-- policy-analyzer-fab:"
    end_marker = "<!-- /policy-analyzer-fab -->"
    if start_marker in content:
        start_idx = content.index(start_marker)
        end_idx = content.index(end_marker) + len(end_marker)
        content = content[:start_idx].rstrip() + "\n" + content[end_idx:].lstrip("\n")
        print(f"[UPDATE] 기존 버튼 교체: {filepath}")
    else:
        print(f"[PATCH] 신규 패치: {filepath}")

    # 백업
    bak = filepath + ".bak"
    shutil.copy2(filepath, bak)

    # </body> 직전에 삽입
    button = BUTTON_HTML.replace("{url}", url)
    if "</body>" not in content:
        print(f"[ERROR] </body> 태그 없음: {filepath}")
        return False

    new_content = content.replace("</body>", button + "\n</body>", 1)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(new_content)

    print(f"[OK] 패치 완료: {filepath}  (백업: {bak})")
    return True


def main():
    url = POLICY_ANALYZER_URL
    if len(sys.argv) > 1:
        url = sys.argv[1]
        print(f"[INFO] 커스텀 URL 사용: {url}")

    success = 0
    for target in TARGETS:
        if patch_file(target, url):
            success += 1

    print(f"\n완료: {success}/{len(TARGETS)} 파일 패치됨")
    print(f"브라우저에서 Ctrl+Shift+R (강제 새로고침) 후 확인하세요.")


if __name__ == "__main__":
    main()
