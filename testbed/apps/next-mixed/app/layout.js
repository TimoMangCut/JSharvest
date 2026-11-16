// Root layout for the App Router routes (a server component: no marker).
export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
