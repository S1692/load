import { useState, useRef, useEffect, FormEvent } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

interface Message {
  id: number;
  type: 'user' | 'bot';
  text: string;
  sources?: { source: string; content: string }[];
}

const ChatIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
  </svg>
);

const CloseIcon = () => (
    <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
    </svg>
);


export default function ChatWidget() {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isOpen]);

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
      `/api/chat/stream?question=${encodeURIComponent(input)}`
    );

    eventSource.onmessage = (event) => {
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
        eventSource.close();
        setIsLoading(false);
      }
    };

    eventSource.onerror = (err) => {
      console.error('EventSource failed:', err);
      setMessages((prev) =>
        prev.map((msg) =>
          msg.id === botMessageId
            ? { ...msg, text: '오류가 발생했습니다.' }
            : msg
        )
      );
      setIsLoading(false);
      eventSource.close();
    };
  };

  return (
    <div className="fixed bottom-5 right-5 z-50">
      {/* Chat Window */}
      {isOpen && (
        <div className="flex flex-col h-[600px] w-96 bg-white dark:bg-gray-800 shadow-2xl rounded-lg border border-gray-200 dark:border-gray-700">
            <header className="bg-gray-100 dark:bg-gray-900 p-3 flex justify-between items-center rounded-t-lg border-b dark:border-gray-700">
                <h2 className="text-lg font-semibold text-gray-800 dark:text-white">카봇</h2>
                <button onClick={() => setIsOpen(false)} className="text-gray-500 hover:text-gray-800 dark:hover:text-white">
                    <CloseIcon />
                </button>
            </header>

            <main className="flex-1 overflow-y-auto p-4 space-y-3 text-sm">
                {messages.map((msg) => (
                <div key={msg.id} className={`flex ${msg.type === 'user' ? 'justify-end' : 'justify-start'}`}>
                    <div className={`max-w-xs lg:max-w-md p-3 rounded-lg ${msg.type === 'user' ? 'bg-blue-500 text-white' : 'bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200'}`}>
                    <div className="prose prose-sm dark:prose-invert max-w-none">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>{msg.text || "..."}</ReactMarkdown>
                    </div>
                    {msg.type === 'bot' && msg.sources && (
                        <div className="mt-2 pt-2 border-t border-gray-300 dark:border-gray-600">
                        <h4 className="text-xs font-bold mb-1">참고 자료:</h4>
                        <ul className="list-disc list-inside text-xs">
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

            <footer className="p-2 border-t dark:border-gray-700">
                <form onSubmit={handleSubmit} className="flex items-center">
                <input
                    type="text"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder="질문을 입력하세요..."
                    className="flex-1 p-2 rounded-lg bg-gray-100 dark:bg-gray-600 border border-gray-300 dark:border-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    disabled={isLoading}
                />
                <button type="submit" className="ml-2 px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 disabled:bg-gray-400" disabled={isLoading}>
                    전송
                </button>
                </form>
            </footer>
        </div>
      )}

      {/* Toggle Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="bg-blue-600 text-white p-4 rounded-full shadow-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
        aria-label="Toggle chat"
      >
        {isOpen ? <CloseIcon/> : <ChatIcon />}
      </button>
    </div>
  );
}
