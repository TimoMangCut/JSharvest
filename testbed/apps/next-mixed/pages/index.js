import { useEffect, useState } from 'react';
import Link from 'next/link';
import dynamic from 'next/dynamic';

console.debug('JSHMARK:entry:index');

// Its chunk is requested only once the button below is clicked.
const Report = dynamic(() => import('../components/report'), { ssr: false });

export default function Home() {
  const [showReport, setShowReport] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => import('../components/telemetry'), 800);
    return () => clearTimeout(t);
  }, []);

  return (
    <main>
      <h1>Next mixed</h1>
      <nav>
        <Link href="/about">About</Link> | <Link href="/items/1">Item 1</Link> |{' '}
        <Link href="/app-linked">App router page</Link>
      </nav>
      <button id="report" onClick={() => setShowReport(true)}>
        Show report
      </button>
      {showReport && <Report />}
    </main>
  );
}
