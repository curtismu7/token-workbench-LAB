import "@testing-library/jest-dom/vitest";

// React Flow measures the DOM; jsdom has no layout, so give it the few browser APIs it reads.
class RO { observe() {} unobserve() {} disconnect() {} }
globalThis.ResizeObserver = globalThis.ResizeObserver || RO;
// The decode result hint watches visibility; jsdom has no IntersectionObserver. Report "visible" so the hint stays hidden in tests.
class IO { constructor(cb) { this.cb = cb; } observe(el) { this.cb?.([{ isIntersecting: true, target: el }]); } unobserve() {} disconnect() {} }
globalThis.IntersectionObserver = globalThis.IntersectionObserver || IO;
globalThis.Element.prototype.scrollIntoView = globalThis.Element.prototype.scrollIntoView || (() => {});
globalThis.DOMMatrixReadOnly = globalThis.DOMMatrixReadOnly || class { constructor() { this.m22 = 1; } };
Object.defineProperties(HTMLElement.prototype, {
  offsetWidth: { configurable: true, get() { return 200; } },
  offsetHeight: { configurable: true, get() { return 80; } },
});

// Some Node versions expose a half-working global localStorage that shadows jsdom's; use a plain in-memory one.
if (typeof globalThis.localStorage?.clear !== "function") {
  const store = new Map();
  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k), clear: () => store.clear() },
  });
}

// The Real-or-mock modal opens on every fresh session; the page tests start with it already dismissed (src/Modal.test.jsx clears these keys).
beforeEach(() => { try { for (const k of ["tw-mode-seen-mock", "tw-mode-seen-real", "tw-mode-hosted-seen-mock"]) sessionStorage.setItem(k, "1"); } catch { /* no sessionStorage */ } });
afterEach(() => { try { sessionStorage.clear(); } catch { /* no sessionStorage */ } });
