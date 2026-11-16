console.debug('JSHMARK:route:item');

export async function getStaticPaths() {
  return { paths: [{ params: { id: '1' } }], fallback: false };
}

export async function getStaticProps({ params }) {
  return { props: { id: params.id } };
}

export default function Item({ id }) {
  return <h1>Item {id}</h1>;
}
