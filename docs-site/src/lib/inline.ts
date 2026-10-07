// Minimal inline Markdown for strings kept in src/data: `code`, **bold**,
// and [text](url). Input is escaped first, so data files cannot inject HTML.

const escape = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

export function inline(src: string, base = ''): string {
  return escape(src)
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_m, text: string, url: string) => {
      const target = url.startsWith('/') ? `${base}${url}` : url;
      const ext = /^https?:/.test(url) ? ' target="_blank" rel="noopener"' : '';
      return `<a href="${target}"${ext}>${text}</a>`;
    });
}
