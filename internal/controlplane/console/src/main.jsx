import React from "react";
import {createRoot} from "react-dom/client";

import App from "./App.jsx";
import "./app.css";

const container = document.getElementById("root");
if (!container) {
  throw new Error("Steward console root is missing.");
}

createRoot(container).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
