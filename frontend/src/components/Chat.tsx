'use client';

import { useState, useRef, useEffect, FormEvent } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

interface Message {
  id: number;
  type: 'user' | 'bot';
  text: string;
  sources?: { source: string; content: string }[];
}

export default function Chat() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;

    const userMessage: Message = { id: Date.now(), type: 'user', text: input };
    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    const botMessageId = Date.now() + 1;
    setMessages((prev) => [...prev, { id: botMessageId, type: 'bot', text: '' }]);

    const eventSource = new EventSource(
      `/api/llm/stream?question=${encodeURIComponent(input)}`
    );

    eventSource.onmessage = (event) => {
      if (event.data === '[DONE]') {
        eventSource.close();
        setIsLoading(false);
        return;
      }

      const data = JSON.parse(event.data);

      if (data.token) {
        setMessages((prev) =>
          prev.map((msg) =>
            msg.id === botMessageId ? { ...msg, text: msg.text + data.token } : msg
          )
        );
      } else if (data.final || data.sources) {
         setMessages((prev) =>
          prev.map((msg) =>
            msg.id === botMessageId ? { ...msg, text: data.final, sources: data.sources } : msg
          )
        );
        eventSource.close();
        setIsLoading(false);
      } else if (data.event === 'end') {
        // This is a custom signal to end, but the final content is in the previous message.
        eventSource.close();
        setIsLoading(false);
      }
    };

    eventSource.onerror = (err) => {
      console.error('EventSource failed:', err);
      setMessages((prev) =>
        prev.map((msg) =>
          msg.id === botMessageId
            ? { ...msg, text: '오류가 발생했습니다. 잠시 후 다시 시도해주세요.' }
            : msg
        )
      );
      setIsLoading(false);
      eventSource.close();
    };
  };

  return (
    <div className="flex flex-col h-screen bg-gray-900 text-white">
      <header className="bg-gray-800 p-4 shadow-md">
        <h1 className="text-xl font-bold">카봇 RAG 데모</h1>
        <p className="text-sm text-gray-400">Ollama, LangChain, Next.js 기반</p>
      </header>

      <main className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg) => (
          <div key={msg.id} className={`flex ${msg.type === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div
              className={`max-w-2xl p-3 rounded-lg ${
                msg.type === 'user' ? 'bg-blue-600' : 'bg-gray-700'
              }`}
            >
              <div className="prose prose-invert prose-sm">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {msg.text || "..."}
                </ReactMarkdown>
              </div>
              {msg.type === 'bot' && msg.sources && (
                <div className="mt-2 pt-2 border-t border-gray-600">
                  <h4 className="text-xs font-bold mb-1">참고 자료:</h4>
                  <ul className="list-disc list-inside text-xs text-gray-400">
                    {msg.sources.map((s, i) => (
                      <li key={i} title={s.content}>{s.source}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        ))}
        <div ref={messagesEndRef} />
      </main>

      <footer className="p-4 bg-gray-800">
        <form onSubmit={handleSubmit} className="flex items-center">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="질문을 입력하세요..."
            className="flex-1 p-2 rounded-l-lg bg-gray-700 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
            disabled={isLoading}
          />
          <button
            type="submit"
            className="px-4 py-2 bg-blue-600 rounded-r-lg hover:bg-blue-700 disabled:bg-gray-500"
            disabled={isLoading}
          >
            {isLoading ? '생성중...' : '전송'}
          </button>
        </form>
      </footer>
    </div>
  );
}
