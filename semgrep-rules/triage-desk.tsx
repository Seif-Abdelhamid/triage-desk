// Test cases for react-dangerously-set-inner-html
export function Bad({ html }: { html: string }) {
  // ruleid: react-dangerously-set-inner-html
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function Good({ text }: { text: string }) {
  // ok: react-dangerously-set-inner-html
  return <div>{text}</div>;
}
