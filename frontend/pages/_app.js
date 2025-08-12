import '../styles/globals.css'
import ChatWidget from '../components/ChatWidget'

function MyApp({ Component, pageProps }) {
  return (
    <>
      <Component {...pageProps} />
      <ChatWidget />
    </>
  )
}

export default MyApp