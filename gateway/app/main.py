import os
import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 환경 변수에서 각 서비스의 URL을 로드
CHATBOT_SERVICE_URL = os.getenv("CHATBOT_SERVICE_URL", "http://chatbot-service:8001")
# AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://auth-service:8002") # 예시

app = FastAPI(
    title="API Gateway",
    description="하위 마이크로서비스로 요청을 프록시하는 게이트웨이",
    version="1.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    logger.info("API 게이트웨이 시작")
    logger.info(f"Chatbot 서비스 URL: {CHATBOT_SERVICE_URL}")

async def _proxy_request(client: httpx.AsyncClient, request: Request, url: str):
    """요청을 특정 URL로 프록시하는 공통 함수"""
    headers = dict(request.headers)
    headers.pop("host", None)
    params = request.query_params
    body = await request.body()

    logger.info(f"Forwarding request: {request.method} {url}")

    try:
        req = client.build_request(
            method=request.method,
            url=url,
            headers=headers,
            params=params,
            content=body
        )
        r = await client.send(req, stream=True)

        response_headers = dict(r.headers)
        response_headers.pop("transfer-encoding", None)

        return StreamingResponse(
            r.aiter_raw(),
            status_code=r.status_code,
            headers=response_headers
        )
    except httpx.RequestError as e:
        logger.error(f"서비스({url}) 연결 오류: {e}")
        return Response(status_code=503, content=f"Service Unavailable: Could not connect to {url}.")

@app.api_route("/chat/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def proxy_to_chatbot_service(request: Request, path: str):
    """/chat/으로 시작하는 모든 요청을 chatbot-service로 포워딩"""
    async with httpx.AsyncClient() as client:
        url = f"{CHATBOT_SERVICE_URL}/{path}"
        return await _proxy_request(client, request, url)

# # auth_service에 대한 프록시 예시 (필요 시 주석 해제)
# @app.api_route("/auth/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
# async def proxy_to_auth_service(request: Request, path: str):
#     """/auth/으로 시작하는 모든 요청을 auth-service로 포워딩"""
#     async with httpx.AsyncClient() as client:
#         url = f"{AUTH_SERVICE_URL}/{path}"
#         return await _proxy_request(client, request, url)

@app.get("/health")
def health_check():
    return {"service": "gateway", "status": "ok"}
