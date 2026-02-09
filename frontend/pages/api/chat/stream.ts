import { NextApiRequest, NextApiResponse } from 'next';

// API Route의 기본 설정을 사용합니다.
// bodyParser를 비활성화하여 스트림을 직접 처리할 수 있도록 합니다.
export const config = {
  api: {
    bodyParser: false,
  },
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).end('Method Not Allowed');
  }

  const { question } = req.query;

  if (!question || typeof question !== 'string') {
    return res.status(400).json({ error: 'Question is required' });
  }

  const gatewayUrl = `${process.env.NEXT_PUBLIC_API_BASE_URL}/chat/generate/stream`;

  try {
    const response = await fetch(gatewayUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream',
      },
      body: JSON.stringify({ question }),
    });

    if (!response.ok || !response.body) {
      const errorText = await response.text();
      console.error('Backend error:', errorText);
      return res.status(response.status).json({ error: 'Failed to connect to backend', detail: errorText });
    }

    // 헤더 설정
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no', // Nginx 프록시 버퍼링 방지
    });

    // 스트림 파이핑
    const reader = response.body.getReader();
    const pump = async () => {
      while (true) {
        const { done, value } = await reader.read();
        if (done) {
          return res.end();
        }
        res.write(value);
      }
    };

    await pump();

  } catch (error) {
    console.error('Error proxying to gateway:', error);
    res.status(502).json({ error: 'Error proxying request to the backend' });
  }
}
