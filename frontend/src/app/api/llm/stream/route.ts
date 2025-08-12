import { NextRequest } from 'next/server';

// Vercel 엣지 런타임은 SSE 스트리밍을 완전히 지원하지 않을 수 있으므로,
// 안정적인 SSE를 위해 Node.js 런타임을 명시적으로 사용합니다.
export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const question = searchParams.get('question');

  if (!question) {
    return new Response('Question is required', { status: 400 });
  }

  // 게이트웨이 URL을 환경 변수에서 가져옵니다.
  const gatewayUrl = `${process.env.NEXT_PUBLIC_API_BASE_URL}/llm/generate/stream`;

  try {
    const response = await fetch(gatewayUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream'
      },
      body: JSON.stringify({ question }),
      // duplex: 'half'는 Node.js fetch에서 스트리밍 요청/응답을 위해 필요합니다.
      // @ts-ignore
      duplex: 'half',
    });

    if (!response.body) {
      return new Response("The backend did not send a response body.", { status: 500 });
    }

    // 백엔드의 스트림을 클라이언트로 직접 파이프합니다.
    const reader = response.body.getReader();
    const stream = new ReadableStream({
      async start(controller) {
        while (true) {
          const { done, value } = await reader.read();
          if (done) {
            break;
          }
          controller.enqueue(value);
        }
        controller.close();
        reader.releaseLock();
      },
    });

    return new Response(stream, {
      headers: {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
      },
    });

  } catch (error) {
    console.error('Error proxying to gateway:', error);
    return new Response('Error proxying request to the backend.', { status: 502 });
  }
}
