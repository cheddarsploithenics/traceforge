import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

afterEach(() => {
  cleanup();
  // Views are routed by URL hash; start every test on the default route.
  window.history.replaceState(null, "", "/");
});
