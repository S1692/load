import { useState } from 'react'

export default function Register() {
  const [form, setForm] = useState({
    username: '',
    password: '',
    email: '',
    full_name: ''
  })
  const [status, setStatus] = useState(null)

  const baseUrl = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000'

  // 입력값 변경 핸들러
  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value })
  }

  // 회원가입
  const handleRegister = async (e) => {
    e.preventDefault()
    setStatus(null)
    const payload = JSON.stringify(form)
    console.log("[REGISTER PAYLOAD]", payload)
    try {
      const response = await fetch(`${baseUrl}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload
      })
      // 응답이 JSON이 아닐 경우 대비
      let result = null
      try {
        result = await response.json()
      } catch (err) {
        setStatus('서버에서 JSON이 아닌 응답을 반환했습니다. (예: 404 HTML)')
        return
      }
      if (response.ok) {
        if (result.input) {
          alert("입력값: " + JSON.stringify(result.input, null, 2));
        }
        setStatus('회원가입 성공! DB에 저장되었습니다.')
        setForm({ username: '', password: '', email: '', full_name: '' })
      } else {
        if (result.input) {
          alert("입력값: " + JSON.stringify(result.input, null, 2));
        }
        setStatus(result.detail || '회원가입 실패')
      }
    } catch (err) {
      setStatus('오류: ' + (err?.message || JSON.stringify(err)))
    }
  }

  // 아이디 중복확인
  const handleCheckUsername = async () => {
    if (!form.username) {
      alert('아이디를 입력하세요.')
      return
    }
    try {
      const res = await fetch(`${baseUrl}/check-username?username=${encodeURIComponent(form.username)}`)
      const data = await res.json()
      if (data.exists) {
        alert('이미 사용 중인 아이디입니다.')
      } else {
        alert('사용 가능한 아이디입니다.')
      }
    } catch {
      alert('서버 오류')
    }
  }

  // 회원 목록 보기
  const handleShowUsers = async () => {
    try {
      const res = await fetch(`${baseUrl}/users`)
      const data = await res.json()
      if (Array.isArray(data.users)) {
        alert(
          data.users.length === 0
            ? '등록된 ��원이 없습니다.'
            : data.users.map(u => `아이디: ${u.username}\n이메일: ${u.email}\n이름: ${u.full_name || ''}\n생성일: ${u.created_at}`).join('\n---\n')
        )
      } else {
        alert('회원 목록을 불러올 수 없습니다.')
      }
    } catch {
      alert('서버 오류')
    }
  }

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <form
        onSubmit={handleRegister}
        className="bg-white p-8 rounded shadow-md w-full max-w-md"
      >
        <h1 className="text-2xl font-bold mb-4 text-center">회원가입</h1>
        <div className="mb-4">
          <label className="block text-gray-700 text-sm font-bold mb-2">아이디</label>
          <div className="flex gap-2">
            <input
              type="text"
              name="username"
              value={form.username}
              onChange={handleChange}
              className="shadow border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
              required
            />
            <button
              type="button"
              onClick={handleCheckUsername}
              className="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded"
            >
              중복확인
            </button>
          </div>
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
        <div className="mb-4">
          <label className="block text-gray-700 text-sm font-bold mb-2">이메일</label>
          <input
            type="email"
            name="email"
            value={form.email}
            onChange={handleChange}
            className="shadow border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
            required
          />
        </div>
        <div className="mb-4">
          <label className="block text-gray-700 text-sm font-bold mb-2">이름(선택)</label>
          <input
            type="text"
            name="full_name"
            value={form.full_name}
            onChange={handleChange}
            className="shadow border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
          />
        </div>
        <button
          type="submit"
          className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded w-full mb-2"
        >
          회원가입
        </button>
        <button
          type="button"
          onClick={handleShowUsers}
          className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded w-full mb-2"
        >
          회원 목록 보기
        </button>
        {status && (
          <p className="mt-4 text-center text-sm text-gray-600">{status}</p>
        )}
        <p className="mt-4 text-center text-sm">
          이미 계정이 있으신가요?{' '}
          <a href="/" className="text-blue-500 hover:underline">
            로그인하기
          </a>
        </p>
      </form>
    </div>
  )
}
