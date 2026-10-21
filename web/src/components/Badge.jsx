import React from "react";

// Outcome words always travel with the colour.
export default function Badge({ kind = "info", children, title }) {
  return <span className={`badge badge--${kind}`} title={title}>{children}</span>;
}
