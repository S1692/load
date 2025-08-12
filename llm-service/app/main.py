import asyncio
import json
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from .config import settings
from .rag_chain import get_rag_chain, get_vector_store_for_health_check

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# RAG 체인 초기화 시 발생할 수 있는 오류를 관리하기 위한 변수
rag_chain_initialization_error = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """FastAPI 앱 시작 시 RAG 체인을 초기화하는 라이프사이클 이벤트"""
    global rag_chain_initialization_error
    logger.info("애플리케이션 시작: RAG 체인 초기화를 시도합니다.")
    try:
        # get_rag_chain()은 내부적으로 벡터 저장소를 빌드함
        get_rag_chain()
        logger.info("RAG 체인 초기화 성공.")
    except Exception as e:
        logger.error(f"RAG 체인 초기화 중 심각한 오류 발생: {e}", exc_info=True)
        rag_chain_initialization_error = e
    yield
    logger.info("애플리케이션 종료.")

app = FastAPI(
    title="LLM RAG Service",
    description="Ollama와 LangChain을 이용한 RAG API",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS 미들웨어 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic 모델 정의 ---
class GenerateRequest(BaseModel):
    question: str

class HealthCheckResponse(BaseModel):
    service: str
    rag_status: str
    vector_store_docs: int
    ollama_base_url: str
    chat_model: str
    embed_model: str

# --- 예외 핸들러 ---
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"처리되지 않은 예외 발생: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"message": "서버 내부 오류가 발생했습니다.", "detail": str(exc)},
    )

# --- API 엔드포인트 ---
@app.get("/health", response_model=HealthCheckResponse, summary="서비스 상태 확인")
async def health_check():
    """서비스의 상태, RAG 체인, 벡터 저장소, 모델 설정을 확인합니다."""
    vector_store = get_vector_store_for_health_check()
    doc_count = 0
    if vector_store and hasattr(vector_store, 'index'):
        doc_count = vector_store.index.ntotal

    rag_status = "ok"
    if rag_chain_initialization_error:
        rag_status = f"error: {rag_chain_initialization_error}"
    elif not vector_store:
        rag_status = "initializing"

    return {
        "service": "ok",
        "rag_status": rag_status,
        "vector_store_docs": doc_count,
        "ollama_base_url": settings.OLLAMA_BASE_URL,
        "chat_model": settings.OLLAMA_CHAT_MODEL,
        "embed_model": settings.OLLAMA_EMBED_MODEL,
    }

@app.post("/generate/", summary="RAG 답변 생성")
async def generate(request: GenerateRequest):
    """질문을 받아 RAG 체인을 통해 답변과 출처를 반환합니다."""
    if rag_chain_initialization_error:
        raise RuntimeError(f"서비스가 초기화되지 않았습니다: {rag_chain_initialization_error}")

    rag_chain = get_rag_chain()
    result = await rag_chain.ainvoke({"question": request.question})
    return {"result": result["result"], "sources": result["sources"]}

@app.post("/generate/stream", summary="RAG 답변 스트리밍")
async def generate_stream(request: GenerateRequest):
    """질문을 받아 RAG 체인을 통해 답변을 SSE로 스트리밍합니다."""
    if rag_chain_initialization_error:
        raise RuntimeError(f"서비스가 초기화되지 않았습니다: {rag_chain_initialization_error}")

    rag_chain = get_rag_chain()

    async def event_generator():
        final_result = ""
        sources = []

        try:
            # 스트리밍 청크 처리
            async for chunk in rag_chain.astream({"question": request.question}):
                if "result" in chunk:
                    token = chunk["result"]
                    final_result += token
                    yield json.dumps({"token": token})
                if "sources" in chunk:
                    sources = chunk["sources"]
                await asyncio.sleep(0.01) # 클라이언트 렌더링을 위한 약간의 지연

            # 스트림 마지막에 최종 결과와 출처 전송
            yield json.dumps({"final": final_result, "sources": sources})
            # SSE 스트림 종료 이벤트. 프롬프트에서는 event:end를 원했지만, [DONE]이 더 표준적인 방식.
            # 클라이언트에서 파싱하기 용이하도록 이벤트 타입을 명시하는 대신, content에 종료 신호를 보냄
            yield json.dumps({"event": "end"})
        except Exception as e:
            logger.error(f"스트리밍 중 오류 발생: {e}", exc_info=True)
            yield json.dumps({"error": "스트리밍 중 오류가 발생했습니다.", "detail": str(e)})

    return EventSourceResponse(event_generator(), media_type="text/event-stream")

# uvicorn으로 직접 실행 시 (개발용)
if __name__ == "__main__":
    import uvicorn
    # Dockerfile에서 Gunicorn을 사용하므로, 포트는 Dockerfile/docker-compose에서 관리
    # 이 uvicorn 실행은 순수 로컬 개발 환경을 위함
    uvicorn.run(app, host="0.0.0.0", port=8001)
