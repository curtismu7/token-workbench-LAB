import React from "react";

// What each tab proves, in presenter words. Every claim is something the server does (docs/architecture.md).
// What each tab proves. Fixed text: this workbench has one cast and no vertical packs, so the story
// system (the {{cast.*}} token family with a vertical supplying names, as in the sibling demos) is not wired in.
export const STORY = [
  { id: "decode", title: "1. Read", proves: "A token is only text. Decoding shows what it says, offline. Anyone can write any claims, so nothing is trusted until the signature is checked." },
  { id: "tester", title: "2. Break", proves: "Fifteen wrong tokens are sent to a stub resource server. A correct one refuses each for the right reason, with the right error." },
  { id: "checker", title: "3. Check", proves: "Five stub authorization servers are probed against OAuth security rules. The FAPI 2.0 pack is UNVERIFIED." },
  { id: "flows", title: "4. Compare", proves: "PKCE, PAR, RAR, DPoP, mTLS and JAR each stop one attack. This is a simulation of the mechanisms, not of any product." },
];

export default function Story({ active }) {
  return (
    <section className="story" aria-label="What each tab proves">
      <ol>
        {STORY.map((s) => (
          <li key={s.id} className={s.id === active ? "now" : ""} aria-current={s.id === active ? "step" : undefined}>
            <strong>{s.title}</strong>
            <span>{s.proves}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}
