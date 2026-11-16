import Document, { Html, Head, Main, NextScript } from 'next/document';

// _document only renders at build time and never ships to the browser, so the
// inline script below exists only in out/index.html, not in any .js file.
export default class MyDocument extends Document {
  render() {
    const isIndex = this.props.__NEXT_DATA__.page === '/';
    return (
      <Html>
        <Head>
          {isIndex && (
            <script
              dangerouslySetInnerHTML={{ __html: "console.debug('JSHMARK:inline:document')" }}
            />
          )}
        </Head>
        <body>
          <Main />
          <NextScript />
        </body>
      </Html>
    );
  }
}
