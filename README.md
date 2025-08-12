# Full-Stack Monorepo with Auth, Chatbot, and Gateway

이 프로젝트는 기존 인증 서비스(`auth-service`)와 프런트엔드에 새로운 RAG 챗봇 기능(`chatbot-service`)과 API 게이트웨이를 통합한 풀스택 애플리케이션입니다.

## 최종 아키텍처

- **`frontend`**: 기존 Next.js 프런트엔드. 모든 페이지에 걸쳐 우하단에 표시되는 플로팅 챗봇 위젯이 추가되었습니다.
- **`gateway`**: FastAPI 기반 API 게이트웨이. `/chat/*` 경로는 `chatbot-service`로, `/auth/*` 경로는 `auth-service`로 라우팅할 수 있는 구조입니다.
- **`service/auth-service`**: 기존 FastAPI 인증 서비스. PostgreSQL 데이터베이스와 연동됩니다.
- **`service/chatbot_service`**: LangChain과 Ollama를 사용하는 새로운 RAG 챗봇 마이크로서비스입니다.
- **`db`**: `auth-service`를 위한 PostgreSQL 데이터베이스입니다.
- **Ollama**: 외부 호스트에서 실행되며, `chatbot-service`가 연결하여 LLM 모델을 사용합니다.

---

## 시작하기

### 1. 전제 조건

- **Docker & Docker Compose**: [Docker 공식 웹사이트](https://www.docker.com/products/docker-desktop/)에서 설치하세요.
- **Ollama**: [Ollama 공식 웹사이트](https://ollama.com/)에서 설치하고, 서버를 실행하세요.

### 2. Ollama 모델 다운로드

터미널에서 Ollama 서버가 실행 중인 상태에서 다음 명령으로 필수 모델을 다운로드합니다.

```bash
ollama pull mistral
ollama pull nomic-embed-text
```

### 3. 환경 변수 설정

1.  **Chatbot 서비스 설정**:
    ```bash
    cp service/chatbot_service/.env.example service/chatbot_service/.env
    ```
    `service/chatbot_service/.env` 파일을 열고 `OLLAMA_BASE_URL`을 자신의 환경에 맞게 수정하세요. (예: `http://host.docker.internal:11434`)

2.  **Auth 서비스 DB 설정** (선택사항):
    `docker-compose.yml`에 DB 접속 정보가 하드코딩되어 있습니다. 변경하려면 `docker-compose.yml`의 `db` 서비스와 `auth-service`의 `DATABASE_URL` 환경 변수를 수정하세요.

### 4. 애플리케이션 실행

프로젝트 루트 디렉토리에서 다음 명령을 실행하여 모든 서비스를 빌드하고 시작합니다.

```bash
docker-compose up --build
```

서비스가 모두 시작되면 다음 주소로 접근할 수 있습니다.
- **프런트엔드**: `http://localhost:3000`
- **게이트웨이**: `http://localhost:8000`
- **PostgreSQL 데이터베이스**: `localhost:5432`

### 5. 사용 방법

1.  웹 브라우저에서 `http://localhost:3000`을 엽니다.
2.  기존 로그인/회원가입 페이지가 표시됩니다.
3.  화면 우하단의 챗봇 아이콘을 클릭하여 챗봇 창을 엽니다.
4.  질문을 입력하고 답변을 확인합니다.

---

## 프로젝트 구조

```
/
├── frontend/             # Next.js 프런트엔드 (플로팅 챗봇 통합)
│   ├── components/ChatWidget.tsx
│   ├── pages/_app.js
│   └── ...
├── gateway/              # FastAPI API 게이트웨이
├── service/
│   ├── auth_service/     # 기존 인증 서비스
│   └── chatbot_service/  # 신규 RAG 챗봇 서비스
├── docker-compose.yml    # 전체 서비스 오케스트레이션
└── README.md             # 이 파일
```

---

## Railway 배포 가이드

이 프로젝트는 각 서비스를 Railway에 독립적으로 배포할 수 있도록 구성되어 있습니다. 아래 가이드를 따라 각 서비스를 배포하세요.

### 1. PostgreSQL 데이터베이스 생성

1.  Railway 대시보드에서 **New Project**를 선택합니다.
2.  **Provision PostgreSQL**을 선택하여 데이터베이스를 생성합니다.
3.  생성된 DB 서비스의 **Variables** 탭에서 접속 정보를 확인합니다. (이 정보는 `auth-service` 설정에 사용됩니다.)

### 2. `auth-service` 배포

1.  **New Service**를 선택하고 **Deploy from GitHub repo**를 선택합니다.
2.  현재 레포지토리를 선택합니다.
3.  **Root Directory**에 `./service`를 입력합니다. Railway가 해당 디렉토리의 `Dockerfile`을 자동으로 감지합니다.
4.  **Variables** 탭에서 `DATABASE_URL` 환경 변수를 추가하고, 1단계에서 생성한 PostgreSQL 데이터베이스의 접속 URL을 입력합니다.
5.  **Deploy**를 누릅니다.

### 3. `chatbot-service` 배포

1.  **New Service** > **Deploy from GitHub repo**를 선택합니다.
2.  **Root Directory**에 `./service/chatbot_service`를 입력합니다.
3.  **Variables** 탭에서 다음 환경 변수를 설정합니다:
    - `OLLAMA_BASE_URL`: 외부에서 접근 가능한 Ollama 서버의 주소.
    - `OLLAMA_CHAT_MODEL`: `mistral`
    - `OLLAMA_EMBED_MODEL`: `nomic-embed-text`
    - `JSON_PATH`: `./data/merged_cbam_data.json`
    - `CORS_ALLOW_ORIGINS`: `*` 또는 배포된 프런트엔드 도메인.
4.  **Networking** 탭에서 **Generate Domain**을 클릭하여 내부 주소를 생성합니다. (이 주소는 `gateway` 설정에 사용됩니다.)
5.  **Deploy**를 누릅니다.

### 4. `gateway` 배포

1.  **New Service** > **Deploy from GitHub repo**를 선택합니다.
2.  **Root Directory**에 `./gateway`를 입력합니다.
3.  **Variables** 탭에서 `CHATBOT_SERVICE_URL` 환경 변수를 추가하고, 3단계에서 생성된 `chatbot-service`의 내부 도메인을 입력합니다.
4.  **Deploy**를 누릅니다. 이 서비스는 외부 인터넷에 노출될 기본 도메인을 받게 됩니다.

### 5. `frontend` 배포

1.  **New Service** > **Deploy from GitHub repo**를 선택합니다.
2.  **Root Directory**에 `./frontend`를 입력합니다.
3.  **Variables** 탭에서 `NEXT_PUBLIC_API_BASE_URL` 환경 변수를 추가하고, 4단계에서 생성된 `gateway`의 공개 도메인을 입력합니다.
4.  **Deploy**를 누릅니다.

### ⚠️ 중요: 포트 하드코딩에 대한 주의사항

현재 각 서비스의 `Dockerfile` 및 `package.json`에는 **포트 번호가 하드코딩**되어 있습니다 (예: `8000`, `8001`, `3000`).

- **문제점**: Railway와 같은 대부분의 PaaS는 앱이 실행될 포트를 동적으로 할당하고 `$PORT` 환경 변수를 통해 전달합니다. 하드코딩된 포트는 이 메커니즘과 충돌하여 배포 실패의 원인이 될 수 있습니다.
- **해결 방안**: 만약 배포 후 서비스가 정상적으로 실행되지 않는다면, 각 서비스의 `Dockerfile`(`CMD` 명령어 부분)과 `frontend/package.json`(`start` 스크립트)에서 하드코딩된 포트 번호를 제거하고, 플랫폼이 제공하는 `$PORT` 변수를 사용하도록 직접 수정해야 할 수 있습니다.

**예시 (`gateway/Dockerfile`):**
```dockerfile
# 수정 전
CMD ["gunicorn", ..., "-b", "0.0.0.0:8000", ...]

# 수정 후
CMD ["gunicorn", ..., "-b", "0.0.0.0:$PORT", ...]
```
이러한 수정은 사용자의 특정 배포 환경에 따라 필요할 수 있으므로, 배포 로그를 주의 깊게 확인하는 것이 좋습니다.
