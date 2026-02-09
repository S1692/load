import re
from datetime import datetime
from typing import List
from langchain_core.retrievers import BaseRetriever
from langchain_core.callbacks import CallbackManagerForRetrieverRun
from langchain_core.documents import Document

class DateSortedRetriever(BaseRetriever):
    """
    BaseRetriever를 상속받아 문서를 날짜 기준으로 정렬하는 커스텀 리트리버.
    메타데이터의 'date' 필드를 YYYY-MM-DD 형식으로 정규화하여 사용합니다.
    """
    base_retriever: BaseRetriever
    ascending: bool = True

    def _normalize_date_str(self, date_str: str) -> str:
        """날짜 문자열을 'YYYY-MM-DD' 형식으로 정규화합니다."""
        # YYYY.MM.DD, YYYY/MM/DD, YYYY-MM-DD 등 다양한 형식을 처리
        return re.sub(r'[./]', '-', date_str)

    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun
    ) -> List[Document]:
        """
        기반 리트리버에서 문서를 가져온 후 날짜 기준으로 정렬합니다.
        """
        # 1. 기반 리트리버로부터 관련 문서 가져오기
        docs = self.base_retriever.get_relevant_documents(query, callbacks=run_manager.get_child())

        # 2. 날짜를 기준으로 문서 정렬
        # 날짜가 없는 문서는 맨 뒤로 보냄 (datetime.min 사용)
        sorted_docs = sorted(
            docs,
            key=lambda doc: datetime.strptime(
                self._normalize_date_str(doc.metadata.get("date", "1900-01-01")), "%Y-%m-%d"
            ) if doc.metadata.get("date") else datetime.min,
            reverse=not self.ascending
        )

        return sorted_docs
