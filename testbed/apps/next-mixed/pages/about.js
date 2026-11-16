import Link from 'next/link';

console.debug('JSHMARK:route:about');

export default function About() {
  return (
    <main>
      <h1>About</h1>
      <Link href="/">Home</Link>
    </main>
  );
}
