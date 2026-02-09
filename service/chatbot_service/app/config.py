from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

class Settings(BaseSettings):
    """
    환경 변수를 관리하는 설정 클래스.
    .env 파일이나 환경 변수에서 값을 로드합니다.
    """
    model_config = SettingsConfigDict(
        # .env 파일은 서비스의 루트 디렉토리에 위치합니다.
        env_file=".env",
        env_file_encoding='utf-8',
        extra='ignore'
    )

    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_CHAT_MODEL: str = "mistral"
    OLLAMA_EMBED_MODEL: str = "nomic-embed-text"
    JSON_PATH: str = "./data/merged_cbam_data.json"

    CORS_ALLOW_ORIGINS_STR: str = "*"

    @property
    def CORS_ALLOW_ORIGINS(self) -> List[str]:
        if self.CORS_ALLOW_ORIGINS_STR == "*":
            return ["*"]
        return [origin.strip() for origin in self.CORS_ALLOW_ORIGINS_STR.split(',')]

# 설정 객체 인스턴스화
settings = Settings()
