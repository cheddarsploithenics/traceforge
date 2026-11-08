import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "./App";
import { takeLoginCodeFromUrl } from "./api/client";
import "./index.css";

const root = document.getElementById("root");
if (!root) throw new Error("Missing #root element");

// Read (and scrub) a single-use sign-in code exactly once, outside React, so
// StrictMode's double-invoked effects can never spend it twice.
const loginCode = takeLoginCodeFromUrl();

createRoot(root).render(
  <StrictMode>
    <App loginCode={loginCode} />
  </StrictMode>,
);
