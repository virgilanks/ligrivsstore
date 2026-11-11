// Mise au point du focus.

/**
 * Attachement Svelte : donne le focus à l'élément dès qu'il est affiché.
 *
 * L'attribut HTML `autofocus` ne suffit pas : Svelte ne l'applique que si
 * aucun autre élément n'a le focus, et le bouton qui ouvre un formulaire
 * (« Nouvelle entrée ») le garde.
 */
export function focusOnMount(node: HTMLElement): void {
  node.focus();
}
