const WIZARD_MAIN_SELECTOR = '.pf-v6-c-wizard__main';

function getWizardScrollContainer(from?: EventTarget | null): HTMLElement | null {
  if (from instanceof HTMLElement) {
    const ancestor = from.closest(WIZARD_MAIN_SELECTOR);
    if (ancestor instanceof HTMLElement) return ancestor;
  }
  return document.querySelector<HTMLElement>(WIZARD_MAIN_SELECTOR);
}

/** Keep wizard step scroll position when focus moves to a control above the viewport. */
export function preserveScrollPosition(action: () => void, eventTarget?: EventTarget | null) {
  const scrollParent = getWizardScrollContainer(eventTarget);
  const scrollTop = scrollParent?.scrollTop ?? 0;
  action();
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      if (scrollParent) scrollParent.scrollTop = scrollTop;
    });
  });
}
