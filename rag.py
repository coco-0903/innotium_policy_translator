"""
RAG (Retrieval-Augmented Generation) 모듈 — Phase 3-3
이노 스마트 플랫폼 기능분析서 기반 지식베이스

의존성:
  pip install chromadb sentence-transformers pymupdf pysqlite3-binary
"""

# Rocky Linux 9 등 구버전 SQLite 환경 대응 (ChromaDB requires sqlite3 >= 3.35.0)
try:
    import pysqlite3
    import sys
    sys.modules['sqlite3'] = pysqlite3
except ImportError:
    pass  # pysqlite3-binary 미설치 시 기본 sqlite3 사용

import os
import re
import logging

logger = logging.getLogger('policy_analyzer')

# ─── 설정 상수 ───────────────────────────────────────
DOCS_DIR       = os.getenv('RAG_DOCS_DIR', './docs/manuals')   # PDF 디렉토리
CHROMA_DIR     = os.getenv('CHROMA_DIR', './chroma_db')
COLLECTION_NAME = 'innotium_manual'
EMBED_MODEL    = 'paraphrase-multilingual-MiniLM-L12-v2'

CHUNK_SIZE     = 500    # 청크 최대 글자 수
CHUNK_OVERLAP  = 100    # 앞 청크와 겹치는 글자 수
DISTANCE_MAX   = 0.6    # 코사인 거리 임계값 (이 값 이상이면 무관한 결과로 제외)

_collection = None   # 싱글턴 컬렉션 캐시


# ─────────────────────────────────────────────────────
# 내부 헬퍼
# ─────────────────────────────────────────────────────

def _get_ef():
    """sentence-transformers 임베딩 함수 반환"""
    try:
        from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction
        return SentenceTransformerEmbeddingFunction(model_name=EMBED_MODEL)
    except Exception as e:
        logger.error(f"임베딩 함수 초기화 실패: {e}")
        raise


def get_collection(force_reload: bool = False):
    """ChromaDB 컬렉션 반환 (싱글턴)"""
    global _collection
    if _collection is not None and not force_reload:
        return _collection
    try:
        import chromadb
        client = chromadb.PersistentClient(path=CHROMA_DIR)
        _collection = client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=_get_ef(),
            metadata={"hnsw:space": "cosine"},
        )
        logger.info(f"ChromaDB 컬렉션 로드 — 청크 수: {_collection.count()}")
        return _collection
    except Exception as e:
        logger.error(f"ChromaDB 초기화 실패: {e}")
        raise


def _list_pdfs(docs_dir: str) -> list[str]:
    """디렉토리에서 PDF 파일 목록 반환 (정렬)"""
    if not os.path.isdir(docs_dir):
        return []
    return sorted(
        os.path.join(docs_dir, f)
        for f in os.listdir(docs_dir)
        if f.lower().endswith('.pdf')
    )


# ─────────────────────────────────────────────────────
# PDF 청킹
# ─────────────────────────────────────────────────────

def _extract_chunks_from_pdf(pdf_path: str, doc_prefix: str = None) -> list[dict]:
    """
    단일 PDF에서 텍스트 추출 → 슬라이딩 윈도우 청킹.

    doc_prefix: 청크 ID 앞에 붙일 문서 식별자 (다중 문서 충돌 방지)
    반환값: [{"id": str, "text": str, "page": int, "source": str}, ...]
    """
    try:
        import fitz  # PyMuPDF
    except ImportError:
        raise ImportError("PyMuPDF 미설치 — pip install pymupdf")

    if not os.path.isfile(pdf_path):
        raise FileNotFoundError(f"PDF 파일 없음: {pdf_path}")

    source_name = os.path.basename(pdf_path)
    prefix = doc_prefix or re.sub(r'[^a-zA-Z0-9가-힣]', '_', source_name)[:20]

    doc = fitz.open(pdf_path)
    total_pages = doc.page_count
    chunks = []
    chunk_idx = 0

    for page_num in range(total_pages):
        page = doc[page_num]
        raw = page.get_text("text")
        if not raw or not raw.strip():
            continue

        # 연속 공백/빈 줄 정리
        text = re.sub(r'\n{3,}', '\n\n', raw)
        text = re.sub(r'[ \t]+', ' ', text).strip()

        pos = 0
        while pos < len(text):
            end = pos + CHUNK_SIZE
            chunk_text = text[pos:end].strip()
            if chunk_text:
                chunks.append({
                    "id": f"{prefix}_p{page_num + 1}_c{chunk_idx}",
                    "text": chunk_text,
                    "page": page_num + 1,
                    "source": source_name,
                })
                chunk_idx += 1
            if end >= len(text):
                break
            pos += CHUNK_SIZE - CHUNK_OVERLAP

    doc.close()
    logger.info(f"청킹 완료 — {source_name}: {total_pages}페이지 → {len(chunks)}개 청크")
    return chunks


# ─────────────────────────────────────────────────────
# 인덱스 빌드
# ─────────────────────────────────────────────────────

def build_index(docs_dir: str = None, pdf_path: str = None) -> dict:
    """
    PDF를 청킹하여 ChromaDB에 인덱싱.

    우선순위:
      1. pdf_path 지정 시 단일 PDF 처리
      2. docs_dir 지정 시 해당 디렉토리의 모든 PDF 처리
      3. 둘 다 없으면 DOCS_DIR 환경변수(기본: ./docs/manuals) 사용

    기존 컬렉션 전체 삭제 후 재구축.
    반환값: {"status": "ok", "chunks": int, "pages": int, "sources": list}
    """
    global _collection

    # 대상 PDF 목록 결정
    if pdf_path:
        pdf_list = [pdf_path]
    else:
        target_dir = docs_dir or DOCS_DIR
        pdf_list = _list_pdfs(target_dir)
        if not pdf_list:
            return {
                "status": "error",
                "message": f"PDF 파일 없음: {target_dir}"
            }

    # 전체 청킹
    all_chunks = []
    failed = []
    for path in pdf_list:
        try:
            chunks = _extract_chunks_from_pdf(path)
            all_chunks.extend(chunks)
        except Exception as e:
            logger.error(f"청킹 실패 — {path}: {e}")
            failed.append({"file": os.path.basename(path), "error": str(e)})

    if not all_chunks:
        return {"status": "error", "message": "청크 추출 실패 (모든 PDF 처리 불가)", "failed": failed}

    # 기존 컬렉션 삭제 후 재생성
    try:
        import chromadb
        client = chromadb.PersistentClient(path=CHROMA_DIR)
        try:
            client.delete_collection(COLLECTION_NAME)
            logger.info("기존 컬렉션 삭제")
        except Exception:
            pass
        _collection = client.create_collection(
            name=COLLECTION_NAME,
            embedding_function=_get_ef(),
            metadata={"hnsw:space": "cosine"},
        )
    except Exception as e:
        logger.error(f"ChromaDB 재생성 실패: {e}")
        return {"status": "error", "message": str(e)}

    # 배치 업서트 (ChromaDB 권장 배치 크기: 100)
    BATCH = 100
    for i in range(0, len(all_chunks), BATCH):
        batch = all_chunks[i:i + BATCH]
        _collection.add(
            ids=[c["id"] for c in batch],
            documents=[c["text"] for c in batch],
            metadatas=[{"page": c["page"], "source": c["source"]} for c in batch],
        )

    sources = sorted(set(c["source"] for c in all_chunks))
    pages_total = max(c["page"] for c in all_chunks)
    logger.info(f"RAG 인덱스 빌드 완료 — {len(sources)}개 문서 / {len(all_chunks)}개 청크")

    result = {
        "status": "ok",
        "chunks": len(all_chunks),
        "sources": sources,
        "source_count": len(sources),
    }
    if failed:
        result["failed"] = failed
    return result


# ─────────────────────────────────────────────────────
# 검색
# ─────────────────────────────────────────────────────

def search(query: str, n_results: int = 5) -> list[dict]:
    """
    쿼리와 유사한 청크 반환.

    거리 임계값(DISTANCE_MAX=0.6) 초과 결과는 제외 — 무관한 내용으로 Claude 오도 방지.
    반환값: [{"text": str, "page": int, "source": str, "distance": float}, ...]
    """
    col = get_collection()
    if col.count() == 0:
        logger.warning("RAG 인덱스가 비어있음 — /api/rag/build 먼저 실행 필요")
        return []

    # 임계값 필터링을 위해 넉넉하게 조회 후 필터
    fetch_n = min(n_results * 2, col.count())
    results = col.query(
        query_texts=[query],
        n_results=fetch_n,
        include=["documents", "metadatas", "distances"],
    )

    hits = []
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        if float(dist) > DISTANCE_MAX:
            continue  # 무관한 결과 제외
        hits.append({
            "text": doc,
            "page": meta.get("page", 0),
            "source": meta.get("source", ""),
            "distance": round(float(dist), 4),
        })
        if len(hits) >= n_results:
            break

    return hits


def search_to_context(query: str, n_results: int = 5) -> str:
    """
    검색 결과를 Claude 컨텍스트 문자열로 변환.

    Claude의 system/user 메시지에 삽입할 참고 자료 블록 생성.
    """
    hits = search(query, n_results)
    if not hits:
        return ""

    lines = ["[기능분析서 참고 자료]\n"]
    for i, h in enumerate(hits, 1):
        lines.append(f"--- 참고 {i} ({h['source']} p.{h['page']}) ---\n{h['text']}\n")
    lines.append("--- 위 내용을 참고하여 답변하세요 ---\n")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────
# 상태 확인
# ─────────────────────────────────────────────────────

def get_status() -> dict:
    """RAG 인덱스 상태 반환"""
    try:
        col = get_collection()
        count = col.count()

        # 인덱싱된 문서 목록 추출
        sources = []
        if count > 0:
            sample = col.get(limit=min(count, 1000), include=["metadatas"])
            seen = set()
            for m in sample["metadatas"]:
                src = m.get("source", "")
                if src and src not in seen:
                    seen.add(src)
                    sources.append(src)
            sources = sorted(sources)

        return {
            "status": "ready" if count > 0 else "empty",
            "chunks": count,
            "source_count": len(sources),
            "sources": sources,
            "chroma_dir": CHROMA_DIR,
            "docs_dir": DOCS_DIR,
            "model": EMBED_MODEL,
            "distance_threshold": DISTANCE_MAX,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
