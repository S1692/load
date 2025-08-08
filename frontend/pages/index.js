import { useState } from 'react'

export default function Home() {
  const [form, setForm] = useState({ username: '', password: '' })
  const [status, setStatus] = useState(null)
  const baseUrl = process.env.NEXT_PUBLIC_API_BASE_URL || ''

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setStatus(null)
    try {
      const response = await fetch(`${baseUrl}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...form, email: '', full_name: '' }) // 백엔드 요구사항 맞춤
      })
      const result = await response.json()
      if (response.ok) {
        setStatus('로그인 성공!')
        setForm({ username: '', password: '' })
      } else {
        setStatus(result.detail || '로그인 실패')
      }
    } catch {
      setStatus('서버 오류')
    }
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <form
        onSubmit={handleSubmit}
        className="bg-white p-8 rounded shadow-md w-full max-w-md"
      >
        <h1 className="text-2xl font-bold mb-4 text-center">로그인</h1>
        <div className="mb-4">
          <label className="block text-gray-700 text-sm font-bold mb-2">아이디</label>
          <input
            type="text"
            name="username"
            value={form.username}
            onChange={handleChange}
            className="shadow border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
            required
          />
        </div>
        <div className="mb-4">
          <label className="block text-gray-700 text-sm font-bold mb-2">비밀번호</label>
          <input
            type="password"
            name="password"
            value={form.password}
            onChange={handleChange}
            className="shadow border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
            required
          />
        </div>
        <button
          type="submit"
          className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded w-full"
        >
          로그인
        </button>
        {status && (
          <p className="mt-4 text-center text-sm text-gray-600">{status}</p>
        )}
        <p className="mt-4 text-center text-sm">
          아직 계정이 없으신가요?{' '}
          <a href="/register" className="text-blue-500 hover:underline">
            회원가입하기
          </a>
        </p>
      </form>
    </div>
  )
}