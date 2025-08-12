# Full-Stack RAG/LLM Project with Next.js, FastAPI, and Ollama

이 프로젝트는 Next.js 프런트엔드, FastAPI 게이트웨이, 그리고 LangChain과 Ollama를 사용하는 FastAPI LLM 마이크로서비스로 구성된 전체 스택 RAG(Retrieval-Augmented Generation) 애플리케이션의 실용적인 예제입니다.

## 아키텍처 개요

- **프런트엔드 (`frontend`)**: Next.js와 React로 구축된 사용자 인터페이스. 서버리스 환경(예: Vercel)에서의 안정적인 SSE 스트리밍을 위해 자체 API 라우트를 통해 게이트웨이와 통신합니다.
- **게이트웨이 (`gateway`)**: FastAPI로 구축된 API 게이트웨이. `/llm/*` 경로의 모든 요청을 내부 `llm-service`로 프록시합니다.
- **LLM 서비스 (`llm-service`)**: FastAPI, LangChain, Ollama를 사용하는 핵심 RAG 마이크로서비스. JSON 문서 로딩, 텍스트 분할, FAISS 벡터 저장소 생성, 그리고 MultiQueryRetriever와 커스텀 날짜 정렬 리트리버를 사용한 답변 생성을 처리합니다.
- **Ollama**: `mistral` (채팅) 및 `nomic-embed-text` (임베딩) 모델을 로컬에서 실행하는 엔진. 이 프로젝트는 Docker 외부의 호스트 머신에서 실행되는 Ollama 인스턴스에 연결됩니다.

---

## 포트 및 라우팅

| 서비스명      | 내부 포트 (Docker) | 외부 노출 포트 (Host) | 도메인 (로컬)            | 프록시 경로                       |
|---------------|--------------------|-----------------------|--------------------------|-----------------------------------|
| `frontend`    | `3000`             | `3000`                | `http://localhost:3000`  | `/api/llm/stream` → Gateway       |
| `gateway`     | `8000`             | `8000`                | `http://localhost:8000`  | `/llm/*` → `llm-service:8001`     |
| `llm-service` | `8001`             | (노출 안 됨)          | `http://llm-service:8001`| (내부 API)                        |

---

## 시작하기

### 1. 전제 조건

- **Docker & Docker Compose**: 컨테이너화된 애플리케이션을 실행하기 위해 필요합니다. [Docker 공식 웹사이트](https://www.docker.com/products/docker-desktop/)에서 설치하세요.
- **Ollama**: 로컬 LLM을 실행하기 위해 필요합니다. [Ollama 공식 웹사이트](https://ollama.com/)에서 설치하세요.

### 2. Ollama 설정 및 모델 다운로드

1.  **Ollama 서버 실행**: 터미널에서 다음 명령을 실행하여 Ollama 서버를 시작합니다.
    ```bash
    ollama serve
    ```
    이 프로세스는 백그라운드에서 계속 실행되어야 합니다.

2.  **필수 모델 다운로드**: 채팅 및 임베딩에 필요한 모델을 다운로드합니다.
    ```bash
    ollama pull mistral
    ollama pull nomic-embed-text
    ```

### 3. 환경 변수 설정

프로젝트에는 `.env` 파일이 필요합니다. 제공된 `.env.example` 파일을 복사하여 시작하세요.

1.  **LLM 서비스 설정**:
    ```bash
    cp llm-service/.env.example llm-service/.env
    ```
    `llm-service/.env` 파일을 열고 `OLLAMA_BASE_URL`을 자신의 환경에 맞게 수정하세요.
    - **Mac/Windows용 Docker Desktop**: `http://host.docker.internal:11434` (기본값)
    - **Linux**: `http://172.17.0.1:11434` (Docker 호스트 IP). `ip addr show docker0` 명령으로 IP를 확인하세요.
    - **Docker 없이 로컬 실행**: `http://localhost:11434`

2.  **프런트엔드 설정** (선택사항, docker-compose가 처리):
    프런트엔드를 로컬에서 `npm run dev`로 직접 실행하려면 `.env.local` 파일을 생성해야 합니다.
    ```bash
    cp frontend/.env.local.example frontend/.env.local
    ```
    `NEXT_PUBLIC_API_BASE_URL`이 게이트웨이 주소(`http://localhost:8000`)를 가리키는지 확인하세요.

### 4. 애플리케이션 실행

모든 설정이 완료되면, 프로젝트 루트 디렉토리에서 다음 명령을 실행하여 모든 서비스를 시작합니다.

```bash
docker-compose up --build
```

- `--build` 플래그는 이미지를 처음 빌드하거나 코드가 변경되었을 때 필요합니다.
- 서비스가 시작되는 데 몇 분 정도 걸릴 수 있습니다. 특히 `llm-service`는 처음 시작할 때 FAISS 벡터 저장소를 생성합니다.

### 5. 사용 방법

1.  웹 브라우저에서 `http://localhost:3000`을 엽니다.
2.  채팅 인터페이스가 나타나면 하단 입력창에 질문을 입력하고 '전송' 버튼을 클릭합니다.
3.  봇이 스트리밍 방식으로 답변을 생성하며, 답변이 완료되면 참고한 출처가 표시됩니다.

---

## 배포 가이드

### 프런트엔드 (Vercel)

1.  GitHub 레포지토리를 Vercel에 연결합니다.
2.  프레임워크 프리셋으로 "Next.js"를 선택합니다.
3.  환경 변수 `NEXT_PUBLIC_API_BASE_URL`에 배포된 게이트웨이의 공개 URL을 설정합니다.

### 백엔드 (Railway, On-premise)

`gateway`와 `llm-service`는 함께 배포되어야 합니다.

1.  **Dockerfile 배포**: Railway와 같은 PaaS는 Dockerfile 배포를 지원합니다. 각 서비스(`gateway`, `llm-service`)를 별도의 서비스로 배포합니다.
2.  **네트워킹**:
    - `llm-service`는 외부 인터넷에 노출될 필요가 없습니다. 내부 네트워크를 통해 `gateway`에서만 접근 가능하도록 설정합니다.
    - `gateway`는 공개적으로 접근 가능한 URL이 있어야 하며, 포트 `8000`을 노출해야 합니다.
3.  **환경 변수**:
    - `gateway`의 `LLM_SERVICE_URL`을 Railway가 제공하는 `llm-service`의 내부 주소로 설정합니다. (예: `http://llm-service.railway.internal:8001`)
    - `llm-service`의 `OLLAMA_BASE_URL`은 원격 Ollama 인스턴스 또는 함께 배포된 Ollama 서비스의 주소를 가리켜야 합니다.

---

## 프로젝트 구조

```
/
├── gateway/              # FastAPI 프록시 (API Gateway)
│   ├── app/main.py
│   ├── Dockerfile
│   └── requirements.txt
├── llm-service/          # FastAPI + LangChain RAG 서비스
│   ├── app/              # 핵심 로직
│   │   ├── config.py
│   │   ├── custom_retriever.py
│   │   ├── main.py
│   │   └── rag_chain.py
│   ├── data/             # 샘플 JSON 데이터
│   ├── .env.example
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/             # Next.js 프런트엔드
│   ├── src/
│   │   ├── app/
│   │   │   ├── api/llm/stream/route.ts (SSE 프록시)
│   │   │   ├── page.tsx
│   │   │   └── layout.tsx
│   │   └── components/Chat.tsx
│   ├── .env.local.example
│   ├── Dockerfile
│   ├── next.config.js
│   └── package.json
├── docker-compose.yml    # 서비스 오케스트레이션
└── README.md             # 이 파일
```
