import os
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import logging

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 환경 변수에서 LLM 서비스 URL 로드, Docker Compose에서 서비스 이름으로 설정
LLM_SERVICE_URL = os.getenv("LLM_SERVICE_URL", "http://llm-service:8001")

app = FastAPI(
    title="API Gateway",
    description="LLM 서비스로 요청을 프록시하는 게이트웨이",
    version="1.0.0"
)

# CORS 미들웨어 설정 (프런트엔드에서 직접 게이트웨이 호출 시 필요)
# llm-service 자체에도 CORS가 있지만, 게이트웨이에도 설정하는 것이 안전함
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # 실제 프로덕션에서는 특정 도메인으로 제한
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    logger.info("API 게이트웨이 시작")
    logger.info(f"LLM 서비스 URL: {LLM_SERVICE_URL}")

@app.api_route("/llm/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_to_llm_service(request: Request, path: str):
    """
    /llm/으로 시작하는 모든 요청을 llm-service로 포워딩합니다.
    스트리밍 응답(SSE)을 지원합니다.
    """
    async with httpx.AsyncClient() as client:
        # 1. llm-service로 보낼 URL 구성
        url = f"{LLM_SERVICE_URL}/{path}"

        # 2. 원본 요청에서 헤더, 쿼리 파라미터, 본문 추출
        headers = dict(request.headers)
        # 호스트 헤더는 프록시되는 서비스의 호스트로 변경해야 함
        headers.pop("host", None)
        params = request.query_params
        body = await request.body()

        logger.info(f"Forwarding request: {request.method} {url}")

        # 3. httpx를 사용하여 llm-service에 요청 전송 (스트리밍 모드)
        try:
            req = client.build_request(
                method=request.method,
                url=url,
                headers=headers,
                params=params,
                content=body
            )
            r = await client.send(req, stream=True)

            # 4. llm-service의 응답을 클라이언트로 스트리밍
            # content-type, content-length 등 필요한 헤더를 그대로 전달
            response_headers = dict(r.headers)
             # Transfer-Encoding은 스트리밍 방식에 따라 자동으로 처리되므로 제거
            response_headers.pop("transfer-encoding", None)

            return StreamingResponse(
                r.aiter_raw(),
                status_code=r.status_code,
                headers=response_headers
            )
        except httpx.RequestError as e:
            logger.error(f"LLM 서비스({url}) 연결 오류: {e}")
            return Response(status_code=503, content="Service Unavailable: Could not connect to LLM service.")

# 게이트웨이 자체의 상태 확인 엔드포인트
@app.get("/health")
def health_check():
    return {"service": "gateway", "status": "ok"}
