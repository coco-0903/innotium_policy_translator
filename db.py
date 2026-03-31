"""
DB 연동 모듈 — MariaDB (innoplatform)
포트: 43306 (비표준)
"""

import os
import re
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


def _snake_to_camel(name: str) -> str:
    """snake_case → camelCase 변환"""
    components = name.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])


def _row_to_camel(row: dict) -> dict:
    """DB row의 모든 키를 camelCase로 변환"""
    return {_snake_to_camel(k): v for k, v in row.items()}


def get_connection():
    return pymysql.connect(**DB_CONFIG)


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
                except Exception as e:
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
