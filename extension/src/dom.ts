// Construction du contenu des pages, sans innerHTML : les titres et les
// identifiants des entrées sont toujours insérés comme du texte.

type Child = Node | string | null | undefined | false;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: { class?: string; text?: string; onclick?: () => void; ariaLabel?: string } = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (props.class) node.className = props.class;
  if (props.text !== undefined) node.textContent = props.text;
  if (props.ariaLabel) node.setAttribute("aria-label", props.ariaLabel);
  if (props.onclick) {
    const action = props.onclick;
    node.addEventListener("click", () => action());
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child);
  }
  return node;
}

export function replace(target: HTMLElement, ...children: Child[]): void {
  target.replaceChildren();
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    target.append(child);
  }
}
