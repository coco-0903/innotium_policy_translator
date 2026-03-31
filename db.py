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
PRODUCT_TABLE_MAP = {
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
                cur.execute("SELECT COUNT(*) AS cnt FROM tb_users")
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
