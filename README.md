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
