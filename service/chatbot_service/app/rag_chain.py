import logging
from typing import List, Tuple, Optional

from langchain_community.chat_models import ChatOllama
from langchain_community.document_loaders import JSONLoader
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.runnables import RunnableLambda, RunnablePassthrough
from langchain_text_splitters import TokenTextSplitter
from langchain.retrievers import MultiQueryRetriever

from .config import settings
from .custom_retriever import DateSortedRetriever

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 전역 변수로 벡터 저장소와 RAG 체인을 관리 (실제 프로덕션에서는 더 정교한 관리 필요)
_vector_store: Optional[FAISS] = None
_rag_chain = None

def _format_docs(docs: List[Document]) -> str:
    """검색된 문서를 프롬프트에 주입하기 좋은 형태의 문자열로 변환합니다."""
    return "\n\n".join(
        f"출처: {doc.metadata.get('source', 'N/A')}\n"
        f"내용: {doc.page_content}"
        for doc in docs
    )

def _get_vector_store() -> FAISS:
    """
    JSON 문서를 로드, 분할, 임베딩하여 FAISS 벡터 저장소를 생성 및 반환합니다.
    이미 생성된 경우 캐시된 저장소를 반환합니다.
    """
    global _vector_store
    if _vector_store:
        return _vector_store

    logger.info(f"'{settings.JSON_PATH}'에서 문서를 로드합니다.")
    try:
        loader = JSONLoader(
            file_path=settings.JSON_PATH,
            jq_schema=".[]",
            content_key="contents",
            json_lines=False,
        )
        documents = loader.load()
    except Exception as e:
        logger.error(f"문서 로드 실패: {e}")
        raise

    logger.info(f"총 {len(documents)}개의 문서를 로드했습니다. 텍스트 분할을 시작합니다.")
    text_splitter = TokenTextSplitter(chunk_size=512, chunk_overlap=50)
    docs = text_splitter.split_documents(documents)

    logger.info(f"{len(docs)}개의 분할된 문서로 임베딩 및 FAISS 벡터 저장소를 생성합니다.")
    embeddings = OllamaEmbeddings(
        base_url=settings.OLLAMA_BASE_URL, model=settings.OLLAMA_EMBED_MODEL
    )

    try:
        _vector_store = FAISS.from_documents(docs, embeddings)
        logger.info("FAISS 벡터 저장소 생성 완료.")
        return _vector_store
    except Exception as e:
        logger.error(f"FAISS 벡터 저장소 생성 실패: {e}")
        # Ollama 연결 문제일 가능성이 높음
        raise ConnectionError(
            f"Ollama({settings.OLLAMA_BASE_URL})에 연결하여 임베딩을 생성할 수 없습니다. "
            "Ollama 서버가 실행 중이고 모델이 pull되었는지 확인하세요."
        )


def get_rag_chain():
    """
    RAG 체인을 초기화하고 반환합니다.
    체인은 MultiQueryRetriever, DateSortedRetriever, 프롬프트, LLM, 출력 파서를 포함합니다.
    """
    global _rag_chain
    if _rag_chain:
        return _rag_chain

    logger.info("RAG 체인을 초기화합니다.")
    vector_store = _get_vector_store()

    # 1. LLM 모델 초기화
    llm = ChatOllama(
        base_url=settings.OLLAMA_BASE_URL,
        model=settings.OLLAMA_CHAT_MODEL,
        temperature=0,
    )

    # 2. 리트리버 설정
    base_retriever = vector_store.as_retriever(search_type="similarity", search_kwargs={"k": 15})

    # 2-1. MultiQueryRetriever 설정
    multiquery_retriever = MultiQueryRetriever.from_llm(
        retriever=base_retriever, llm=llm
    )

    # 2-2. DateSortedRetriever 설정 (오름차순)
    final_retriever = DateSortedRetriever(base_retriever=multiquery_retriever, ascending=True)

    # 3. 프롬프트 템플릿 설정
    system_prompt = (
        "당신은 '카봇'이라는 이름을 가진, 친절하고 명료한 AI 어시스턴트입니다. "
        "주어진 문서를 바탕으로 사용자의 질문에 한국어로 답변해주세요. "
        "문서에 질문과 관련된 내용이 없다면, 아는 내용을 바탕으로 답변하지 말고 '주어진 문서에서는 해당 내용을 찾을 수 없습니다.'라고 솔직하게 말해주세요. "
        "답변은 항상 완전한 문장으로 정중하게 마무리하세요."
    )
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            ("human", "문서:\n{context}\n\n질문: {question}"),
        ]
    )

    # 4. RAG 체인 구성
    rag_chain_from_docs = (
        RunnablePassthrough.assign(context=(RunnableLambda(_format_docs)))
        | prompt
        | llm
        | StrOutputParser()
    )

    _rag_chain = (
        RunnablePassthrough.assign(
            context_docs=RunnableLambda(
                lambda x: final_retriever.get_relevant_documents(x["question"])
            )
        )
        | {
            "result": rag_chain_from_docs,
            "sources": lambda x: [
                {"source": doc.metadata.get("source"), "content": doc.page_content}
                for doc in x["context_docs"]
            ],
        }
    )

    logger.info("RAG 체인 초기화 완료.")
    return _rag_chain

def get_vector_store_for_health_check() -> Optional[FAISS]:
    """/health 엔드포인트에서 사용할 벡터 저장소 인스턴스를 반환합니다."""
    return _vector_store
