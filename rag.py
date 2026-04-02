"""
RAG (Retrieval-Augmented Generation) 모듈 — Phase 3-3
이노 스마트 플랫폼 에이전트 기능 분석서 기반 지식베이스

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

PDF_PATH = os.getenv('RAG_PDF_PATH', './docs/feature_manual.pdf')
CHROMA_DIR = os.getenv('CHROMA_DIR', './chroma_db')
COLLECTION_NAME = 'innotium_manual'
EMBED_MODEL = 'paraphrase-multilingual-MiniLM-L12-v2'

CHUNK_SIZE = 500      # 청크 최대 글자 수
CHUNK_OVERLAP = 100   # 앞 청크와 겹치는 글자 수

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
        logger.info(f"ChromaDB 컬렉션 로드 — 문서 수: {_collection.count()}")
        return _collection
    except Exception as e:
        logger.error(f"ChromaDB 초기화 실패: {e}")
        raise


# ─────────────────────────────────────────────────────
# PDF 청킹
# ─────────────────────────────────────────────────────

def extract_chunks(pdf_path: str) -> list[dict]:
    """
    PDF에서 텍스트를 추출하고 오버랩 슬라이딩 윈도우로 청크 분할.

    반환값: [{"id": str, "text": str, "page": int, "source": str}, ...]
    """
    try:
        import fitz  # PyMuPDF
    except ImportError:
        raise ImportError("PyMuPDF 미설치 — pip install pymupdf")

    if not os.path.isfile(pdf_path):
        raise FileNotFoundError(f"PDF 파일 없음: {pdf_path}")

    doc = fitz.open(pdf_path)
    chunks = []
    chunk_idx = 0

    for page_num in range(len(doc)):
        page = doc[page_num]
        raw = page.get_text("text")
        if not raw or not raw.strip():
            continue

        # 연속 공백/빈 줄 정리
        text = re.sub(r'\n{3,}', '\n\n', raw)
        text = re.sub(r'[ \t]+', ' ', text).strip()

        # 슬라이딩 윈도우 청킹
        pos = 0
        while pos < len(text):
            end = pos + CHUNK_SIZE
            chunk_text = text[pos:end].strip()
            if chunk_text:
                chunks.append({
                    "id": f"p{page_num + 1}_c{chunk_idx}",
                    "text": chunk_text,
                    "page": page_num + 1,
                    "source": os.path.basename(pdf_path),
                })
                chunk_idx += 1
            if end >= len(text):
                break
            pos += CHUNK_SIZE - CHUNK_OVERLAP

    doc.close()
    logger.info(f"PDF 청킹 완료 — {len(doc.page_count if hasattr(doc, 'page_count') else [])}페이지 → {len(chunks)}개 청크")
    return chunks


def _extract_chunks_safe(pdf_path: str) -> list[dict]:
    """extract_chunks 래퍼 — fitz page_count 접근 버그 방지"""
    try:
        import fitz
    except ImportError:
        raise ImportError("PyMuPDF 미설치 — pip install pymupdf")

    if not os.path.isfile(pdf_path):
        raise FileNotFoundError(f"PDF 파일 없음: {pdf_path}")

    doc = fitz.open(pdf_path)
    total_pages = doc.page_count
    chunks = []
    chunk_idx = 0

    for page_num in range(total_pages):
        page = doc[page_num]
        raw = page.get_text("text")
        if not raw or not raw.strip():
            continue

        text = re.sub(r'\n{3,}', '\n\n', raw)
        text = re.sub(r'[ \t]+', ' ', text).strip()

        pos = 0
        while pos < len(text):
            end = pos + CHUNK_SIZE
            chunk_text = text[pos:end].strip()
            if chunk_text:
                chunks.append({
                    "id": f"p{page_num + 1}_c{chunk_idx}",
                    "text": chunk_text,
                    "page": page_num + 1,
                    "source": os.path.basename(pdf_path),
                })
                chunk_idx += 1
            if end >= len(text):
                break
            pos += CHUNK_SIZE - CHUNK_OVERLAP

    doc.close()
    logger.info(f"PDF 청킹 완료 — {total_pages}페이지 → {len(chunks)}개 청크")
    return chunks


# ─────────────────────────────────────────────────────
# 인덱스 빌드
# ─────────────────────────────────────────────────────

def build_index(pdf_path: str = None) -> dict:
    """
    PDF를 청킹하여 ChromaDB에 인덱싱.

    기존 컬렉션을 초기화하고 새로 구축.
    반환값: {"status": "ok", "chunks": int, "pages": int}
    """
    if pdf_path is None:
        pdf_path = PDF_PATH

    global _collection
    chunks = _extract_chunks_safe(pdf_path)
    if not chunks:
        return {"status": "error", "message": "청크 추출 실패 (PDF 텍스트 없음)"}

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
    for i in range(0, len(chunks), BATCH):
        batch = chunks[i:i + BATCH]
        _collection.add(
            ids=[c["id"] for c in batch],
            documents=[c["text"] for c in batch],
            metadatas=[{"page": c["page"], "source": c["source"]} for c in batch],
        )

    pages = max(c["page"] for c in chunks)
    logger.info(f"RAG 인덱스 빌드 완료 — {pages}페이지 {len(chunks)}개 청크")
    return {"status": "ok", "chunks": len(chunks), "pages": pages}


# ─────────────────────────────────────────────────────
# 검색
# ─────────────────────────────────────────────────────

def search(query: str, n_results: int = 5) -> list[dict]:
    """
    쿼리와 유사한 청크 반환.

    반환값: [{"text": str, "page": int, "source": str, "distance": float}, ...]
    """
    col = get_collection()
    if col.count() == 0:
        logger.warning("RAG 인덱스가 비어있음 — /api/rag/build 먼저 실행 필요")
        return []

    results = col.query(
        query_texts=[query],
        n_results=min(n_results, col.count()),
        include=["documents", "metadatas", "distances"],
    )

    hits = []
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        hits.append({
            "text": doc,
            "page": meta.get("page", 0),
            "source": meta.get("source", ""),
            "distance": round(float(dist), 4),
        })

    return hits


def search_to_context(query: str, n_results: int = 5) -> str:
    """
    검색 결과를 Claude 컨텍스트 문자열로 변환.

    Claude의 system/user 메시지에 삽입할 참고 자료 블록 생성.
    """
    hits = search(query, n_results)
    if not hits:
        return ""

    lines = ["[기능분석서 참고 자료]\n"]
    for i, h in enumerate(hits, 1):
        lines.append(f"--- 참고 {i} (p.{h['page']}) ---\n{h['text']}\n")
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
        return {
            "status": "ready" if count > 0 else "empty",
            "chunks": count,
            "chroma_dir": CHROMA_DIR,
            "pdf_path": PDF_PATH,
            "model": EMBED_MODEL,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
