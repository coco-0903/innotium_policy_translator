"""
DB 연동 모듈 — MariaDB (innoplatform)
포트: 43306 (비표준)
Connection Pooling + Few-Shot 피드백 테이블 포함
"""

import os
import json
import threading
import pymysql
import pymysql.cursors

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DB_CONFIG = {
    'host':     os.getenv('DB_HOST', '127.0.0.1'),
    'port':     int(os.getenv('DB_PORT', '43306')),
    'user':     os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASS', ''),
    'database': os.getenv('DB_NAME', 'innoplatform'),
    'charset':  'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor,
}

# 제품 → 테이블 매핑
# innoecm 추가: tb_agent_policy (실제 DB 확인 완료)
PRODUCT_TABLE_MAP = {
    'innoecm':          ('tb_agent_policy',                        'agent_policy_id',              'agent_policy_name'),
    'securezone':       ('tb_secure_zone_agent_policy',        'sz_agent_policy_id',       'sz_agent_policy_name'),
    'securezone_acl':   ('tb_secure_zone_access_control_policy','sz_access_control_policy_id','sz_access_control_policy_name'),
    'controlsuite':     ('tb_control_suite',                   'csu_id',                   'csu_name'),
    'ransomcruncher':   ('tb_ransom_cruncher_detect_policy',   'rc_detect_policy_id',      'rc_detect_policy_name'),
    'ransomcruncher_rdp': ('tb_ransom_cruncher_rdp_policy',    'rc_rdp_policy_id',         'rc_rdp_policy_name'),
    'npouch':           ('tb_npouch_policy',                   'np_policy_id',             'np_policy_name'),
    'npouch_origin':    ('tb_npouch_origin_protect_policy',    'np_origin_protect_policy_id','origin_protect_policy_name'),
    'innomark':         ('tb_inno_mark_policy',                'im_policy_id',             'im_policy_name'),
    'innomark_rdp':     ('tb_inno_mark_rdp_policy',            'im_rdp_policy_id',         'im_rdp_policy_name'),
    'lizardbackup':     ('tb_lizard_backup_policy',            'lb_policy_id',             'lb_policy_name'),
    'lizardbackup_agent': ('tb_lizard_agent_policy',           'lb_agent_policy_id',       'lb_agent_policy_name'),
    'unified':          ('tb_unified_agent_policy',            'unified_agent_policy_id',  'unified_agent_policy_name'),
}


# ═══════════════════════════════════════════════════
# Connection Pool (간단한 thread-local 방식)
# DBUtils 패키지가 있으면 PooledDB 사용, 없으면 직접 연결
# ═══════════════════════════════════════════════════

_pool = None
_pool_lock = threading.Lock()


def _init_pool():
    global _pool
    try:
        from dbutils.pooled_db import PooledDB
        _pool = PooledDB(
            creator=pymysql,
            maxconnections=10,
            mincached=2,
            maxcached=5,
            blocking=True,
            **{k: v for k, v in DB_CONFIG.items() if k != 'cursorclass'},
            cursorclass=pymysql.cursors.DictCursor,
        )
    except ImportError:
        _pool = None  # DBUtils 없으면 직접 연결 사용


def get_connection():
    global _pool
    with _pool_lock:
        if _pool is None:
            _init_pool()
    if _pool is not None:
        return _pool.connection()
    return pymysql.connect(**DB_CONFIG)


# ═══════════════════════════════════════════════════
# 유틸리티
# ═══════════════════════════════════════════════════

def _snake_to_camel(name: str) -> str:
    """snake_case → camelCase 변환"""
    components = name.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])


def _row_to_camel(row: dict) -> dict:
    """DB row의 모든 키를 camelCase로 변환"""
    return {_snake_to_camel(k): v for k, v in row.items()}


# ═══════════════════════════════════════════════════
# 피드백 테이블 초기화
# ═══════════════════════════════════════════════════

_feedback_table_ready = False
_feedback_lock = threading.Lock()


def _ensure_feedback_table():
    global _feedback_table_ready
    if _feedback_table_ready:
        return
    with _feedback_lock:
        if _feedback_table_ready:
            return
        try:
            conn = get_connection()
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS pa_feedback_examples (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        product VARCHAR(50),
                        feature VARCHAR(20) NOT NULL,
                        policy_json MEDIUMTEXT NOT NULL,
                        analysis_result MEDIUMTEXT NOT NULL,
                        rating TINYINT NOT NULL COMMENT '1=좋아요, -1=싫어요',
                        created_at DATETIME DEFAULT NOW(),
                        INDEX idx_feature_product (feature, product),
                        INDEX idx_rating (rating)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """)
            conn.commit()
            conn.close()
            _feedback_table_ready = True
        except Exception:
            pass  # 테이블 생성 실패해도 앱은 동작


# ═══════════════════════════════════════════════════
# 기존 함수들
# ═══════════════════════════════════════════════════

def get_dashboard() -> dict:
    """제품별 정책 수 + 사용자/부서 현황 요약"""
    result = {'products': {}, 'users': 0, 'groups': 0, 'connected': True}
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            for product, (table, pk, name_col) in PRODUCT_TABLE_MAP.items():
                try:
                    cur.execute(f"SELECT COUNT(*) AS cnt FROM `{table}`")
                    row = cur.fetchone()
                    result['products'][product] = row['cnt'] if row else 0
                except Exception:
                    result['products'][product] = -1

            try:
                cur.execute("SELECT COUNT(*) AS cnt FROM tb_users WHERE member_status = 1")
                result['users'] = cur.fetchone()['cnt']
            except Exception:
                pass

            try:
                cur.execute("SELECT COUNT(*) AS cnt FROM tb_groups")
                result['groups'] = cur.fetchone()['cnt']
            except Exception:
                pass
        conn.close()
    except Exception as e:
        result['connected'] = False
        result['error'] = str(e)
    return result


def get_all_policies() -> dict:
    """전체 정책 목록 (제품별)"""
    result = {}
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            for product, (table, pk, name_col) in PRODUCT_TABLE_MAP.items():
                try:
                    cur.execute(
                        f"SELECT `{pk}` AS id, `{name_col}` AS name, "
                        f"create_datetime, update_datetime "
                        f"FROM `{table}` ORDER BY `{pk}` DESC LIMIT 100"
                    )
                    rows = cur.fetchall()
                    result[product] = [_row_to_camel(r) for r in rows]
                except Exception:
                    result[product] = []
        conn.close()
    except Exception as e:
        return {'error': str(e)}
    return result


def get_policy_detail(product: str, policy_id: int) -> dict:
    """특정 정책 상세 JSON"""
    if product not in PRODUCT_TABLE_MAP:
        return {'error': f'알 수 없는 제품: {product}'}
    table, pk, _ = PRODUCT_TABLE_MAP[product]
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(f"SELECT * FROM `{table}` WHERE `{pk}` = %s", (policy_id,))
            row = cur.fetchone()
        conn.close()
        if not row:
            return {'error': '정책을 찾을 수 없습니다'}
        return _row_to_camel(row)
    except Exception as e:
        return {'error': str(e)}


# ═══════════════════════════════════════════════════
# Phase 2-1: 통합 정책 조립
# ═══════════════════════════════════════════════════

# manager_menu_id → (제품명, 테이블, PK컬럼, 이름컬럼)
# 실제 DB에서 확인된 값: 100 = innoECM (tb_agent_policy)
# 나머지는 정책 할당 데이터가 생기면 확인 후 추가
MENU_ID_MAP = {
    100: ('innoECM',         'tb_agent_policy',                    'agent_policy_id',              'agent_policy_name'),
    200: ('SecureZone',      'tb_secure_zone_agent_policy',        'sz_agent_policy_id',           'sz_agent_policy_name'),
    201: ('SecureZone ACL',  'tb_secure_zone_access_control_policy','sz_access_control_policy_id', 'sz_access_control_policy_name'),
    300: ('RansomCruncher',  'tb_ransom_cruncher_detect_policy',   'rc_detect_policy_id',          'rc_detect_policy_name'),
    301: ('RC-RDP',          'tb_ransom_cruncher_rdp_policy',      'rc_rdp_policy_id',             'rc_rdp_policy_name'),
    400: ('nPouch',          'tb_npouch_policy',                   'np_policy_id',                 'np_policy_name'),
    401: ('nPouch 원본보호',  'tb_npouch_origin_protect_policy',   'np_origin_protect_policy_id',  'origin_protect_policy_name'),
    500: ('LizardBackup',    'tb_lizard_backup_policy',            'lb_policy_id',                 'lb_policy_name'),
    600: ('innoMark',        'tb_inno_mark_policy',                'im_policy_id',                 'im_policy_name'),
}


def _get_policy_name_by_menu(cur, manager_menu_id: int, policy_id: int) -> str:
    """manager_menu_id + policy_id로 정책 이름 조회"""
    if manager_menu_id not in MENU_ID_MAP:
        return f'정책#{policy_id}'
    product_label, table, pk_col, name_col = MENU_ID_MAP[manager_menu_id]
    try:
        cur.execute(f"SELECT `{name_col}` FROM `{table}` WHERE `{pk_col}` = %s", (policy_id,))
        row = cur.fetchone()
        if row:
            return row.get(name_col, f'정책#{policy_id}')
    except Exception:
        pass
    return f'정책#{policy_id}'


def get_unified_policy_full(policy_id: int) -> dict:
    """통합 정책 상세 조회
    실제 DB 구조: tb_unified_agent_policy에는 제품별 FK 컬럼 없음.
    제품별 정책 연결은 tb_user_agent_multi_policy / tb_group_agent_multi_policy를 통해 이뤄짐.
    여기서는 unified 정책 기본 정보 + 해당 정책에 할당된 사용자/부서 현황을 반환.
    """
    result = {'unified': {}, 'assigned_users': [], 'assigned_groups': [], 'policy_id': policy_id}
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM tb_unified_agent_policy WHERE unified_agent_policy_id = %s",
                (policy_id,)
            )
            unified_row = cur.fetchone()
            if not unified_row:
                return {'error': f'통합 정책 #{policy_id}를 찾을 수 없습니다'}
            result['unified'] = _row_to_camel(unified_row)

            # 이 정책이 할당된 사용자 목록 (tb_user_agent_multi_policy → tb_users)
            try:
                cur.execute(
                    """SELECT u.user_id, u.member_id, u.user_name
                       FROM tb_user_agent_multi_policy m
                       JOIN tb_users u ON m.user_id = u.user_id
                       WHERE m.policy_id = %s AND u.member_status = 1
                       LIMIT 50""",
                    (policy_id,)
                )
                result['assigned_users'] = [_row_to_camel(r) for r in (cur.fetchall() or [])]
            except Exception:
                pass

            # 이 정책이 할당된 부서 목록 (tb_group_agent_multi_policy → tb_groups)
            try:
                cur.execute(
                    """SELECT g.group_id, g.group_name
                       FROM tb_group_agent_multi_policy m
                       JOIN tb_groups g ON m.group_id = g.group_id
                       WHERE m.policy_id = %s
                       LIMIT 50""",
                    (policy_id,)
                )
                result['assigned_groups'] = [_row_to_camel(r) for r in (cur.fetchall() or [])]
            except Exception:
                pass

        conn.close()
    except Exception as e:
        result['error'] = str(e)
    return result


# ═══════════════════════════════════════════════════
# Phase 2-2: 사용자/부서별 정책 조회
# ═══════════════════════════════════════════════════

def get_users_list(limit: int = 200) -> list:
    """실 사용자 목록 (member_status=1)
    실제 컬럼: user_id(PK int), member_id(로그인ID varchar), user_name, email
    """
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_id, member_id, user_name, email, member_status, create_datetime "
                "FROM tb_users WHERE member_status = 1 ORDER BY user_id LIMIT %s",
                (limit,)
            )
            rows = cur.fetchall()
        conn.close()
        return [_row_to_camel(r) for r in (rows or [])]
    except Exception as e:
        return [{'error': str(e)}]


def get_groups_list(limit: int = 200) -> list:
    """부서/그룹 목록"""
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT group_id, group_name, create_datetime "
                "FROM tb_groups ORDER BY group_id LIMIT %s",
                (limit,)
            )
            rows = cur.fetchall()
        conn.close()
        return [_row_to_camel(r) for r in (rows or [])]
    except Exception as e:
        return [{'error': str(e)}]


def get_user_policies(user_id: int) -> dict:
    """사용자에 할당된 제품별 정책 조회
    실제 테이블: tb_user_agent_policy (user_id, pc_connect_server_id, manager_menu_id, policy_id)
    manager_menu_id로 어떤 제품 정책인지 판단 후 정책명 조회
    """
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_id, member_id, user_name, email FROM tb_users WHERE user_id = %s",
                (user_id,)
            )
            user = cur.fetchone()

            cur.execute(
                """SELECT manager_menu_id, policy_id, create_datetime
                   FROM tb_user_agent_policy
                   WHERE user_id = %s
                   ORDER BY manager_menu_id""",
                (user_id,)
            )
            rows = cur.fetchall()

            # 각 행에 제품명 + 정책명 보강
            enriched = []
            for row in (rows or []):
                menu_id = row.get('manager_menu_id')
                pol_id  = row.get('policy_id')
                product_label = MENU_ID_MAP.get(menu_id, (f'메뉴#{menu_id}',))[0]
                policy_name   = _get_policy_name_by_menu(cur, menu_id, pol_id)
                enriched.append({
                    **_row_to_camel(row),
                    'productLabel': product_label,
                    'policyName':   policy_name,
                })
        conn.close()
        return {
            'user': _row_to_camel(user) if user else {},
            'policies': enriched,
        }
    except Exception as e:
        return {'error': str(e)}


def get_group_policies(group_id: int) -> dict:
    """부서에 할당된 제품별 정책 조회
    실제 테이블: tb_group_agent_policy (group_id, manager_menu_id, policy_id)
    """
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT group_id, group_name FROM tb_groups WHERE group_id = %s",
                (group_id,)
            )
            group = cur.fetchone()

            cur.execute(
                """SELECT manager_menu_id, policy_id, create_datetime
                   FROM tb_group_agent_policy
                   WHERE group_id = %s
                   ORDER BY manager_menu_id""",
                (group_id,)
            )
            rows = cur.fetchall()

            enriched = []
            for row in (rows or []):
                menu_id = row.get('manager_menu_id')
                pol_id  = row.get('policy_id')
                product_label = MENU_ID_MAP.get(menu_id, (f'메뉴#{menu_id}',))[0]
                policy_name   = _get_policy_name_by_menu(cur, menu_id, pol_id)
                enriched.append({
                    **_row_to_camel(row),
                    'productLabel': product_label,
                    'policyName':   policy_name,
                })
        conn.close()
        return {
            'group': _row_to_camel(group) if group else {},
            'policies': enriched,
        }
    except Exception as e:
        return {'error': str(e)}


# ═══════════════════════════════════════════════════
# Phase 2-4: 정책 변경 이력 타임라인
# ═══════════════════════════════════════════════════

def get_policy_timeline(limit: int = 30) -> list:
    """전체 정책 테이블에서 최근 변경 이력 (update_datetime 기준 정렬)"""
    items = []
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            for product, (table, pk, name_col) in PRODUCT_TABLE_MAP.items():
                try:
                    cur.execute(
                        f"SELECT %s AS product, `{pk}` AS policy_id, "
                        f"`{name_col}` AS policy_name, "
                        f"create_datetime, update_datetime "
                        f"FROM `{table}` ORDER BY update_datetime DESC LIMIT 10",
                        (product,)
                    )
                    rows = cur.fetchall()
                    items.extend([_row_to_camel(r) for r in rows])
                except Exception:
                    pass
        conn.close()
        items.sort(key=lambda x: x.get('updateDatetime') or x.get('createDatetime') or '', reverse=True)
        return items[:limit]
    except Exception as e:
        return [{'error': str(e)}]


# ═══════════════════════════════════════════════════
# 피드백 (Few-Shot 예제 축적)
# ═══════════════════════════════════════════════════

def save_feedback(policy_json: str, analysis_result: str, feature: str, rating: int, product: str = '') -> bool:
    """분석 결과에 대한 평점 저장"""
    _ensure_feedback_table()
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO pa_feedback_examples "
                "(product, feature, policy_json, analysis_result, rating) "
                "VALUES (%s, %s, %s, %s, %s)",
                (product or None, feature, policy_json, analysis_result, rating)
            )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def get_feedback_examples(feature: str, product: str = '', limit: int = 3) -> list:
    """좋은 평가(rating=1) 예시 반환 — 프롬프트 few-shot용"""
    _ensure_feedback_table()
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            if product:
                cur.execute(
                    "SELECT policy_json, analysis_result FROM pa_feedback_examples "
                    "WHERE feature = %s AND rating = 1 AND product = %s "
                    "ORDER BY created_at DESC LIMIT %s",
                    (feature, product, limit)
                )
            else:
                cur.execute(
                    "SELECT policy_json, analysis_result FROM pa_feedback_examples "
                    "WHERE feature = %s AND rating = 1 "
                    "ORDER BY created_at DESC LIMIT %s",
                    (feature, limit)
                )
            rows = cur.fetchall()
        conn.close()
        return rows or []
    except Exception:
        return []


# ═══════════════════════════════════════════════════
# 분석 이력 저장/조회
# ═══════════════════════════════════════════════════

def _ensure_history_table():
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS pa_history (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    analysis_type VARCHAR(20) NOT NULL,
                    product VARCHAR(60) DEFAULT '',
                    input_summary TEXT,
                    result_text MEDIUMTEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_hist_created (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            """)
        conn.commit()
        conn.close()
    except Exception:
        pass


def save_history(analysis_type: str, product: str, input_summary: str, result_text: str) -> bool:
    """분석 이력 저장 (translate/simulate/diagnose/diff/log/chat)"""
    _ensure_history_table()
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO pa_history (analysis_type, product, input_summary, result_text) "
                "VALUES (%s, %s, %s, %s)",
                (analysis_type, product or '', (input_summary or '')[:300], (result_text or '')[:12000])
            )
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False


def get_history(limit: int = 20) -> list:
    """최근 분석 이력 반환"""
    _ensure_history_table()
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, analysis_type, product, input_summary, created_at "
                "FROM pa_history ORDER BY created_at DESC LIMIT %s",
                (min(int(limit), 50),)
            )
            rows = cur.fetchall()
        conn.close()
        return rows or []
    except Exception:
        return []
