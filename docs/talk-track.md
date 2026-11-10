# Talk track (4-6 minutes)

In Mock (the default) everything on screen is a stub running on this machine. Say so first, and point at the MOCK banner. If the owner turned Real on, the banner says REAL and names the one issuer it calls.

## Pitch (one sentence)

"This shows what a token says, what a correct API does with a wrong one, how an authorization server scores against OAuth security rules, and what each add-on protection actually stops, all offline with mock tokens."

## Before you start

Run `npm run build` and `npm start`, open http://127.0.0.1:5910/. Check the header shows the app ready.

## Live steps

1. **Decode / Trace tab.** Click **Agent token** (under "Mint a sample token"), then **Decode**. Say: "This token is minted by a stub and labelled mock. Decoding is just reading text. Each claim has a plain-English line; note `act`, the agent acting for the user."
2. **Same tab.** Tick **Verify the signature against the stub JWKS** and decode again. Say: "Now the signature is checked against the stub's keys. Anyone can write claims; only the signature says who wrote them."
3. **Same tab.** Click **Expired**, then Decode. Say: "The signature is still valid, but the expiry status flags it."
4. **Wrong-token tester tab.** Click **Run all**. Say: "Fifteen tokens go to a stub resource server. The first is a correct control and is accepted. The rest are refused: wrong audience, wrong scope, expired, alg none, algorithm confusion, tampered and forged signatures, unknown key id, and more."
5. **Same tab.** Open one case such as **Wrong audience** and read the status, the `WWW-Authenticate` error, the check that failed and the teach-me text. Say: "Each refusal is for a specific reason and a specific error code."
6. **Profile checker tab.** Pick the stub profile `good`, pack **Both packs**, click **Run checker**; then pick `no-pkce` and run again. Say: "Five stub authorization servers, each broken in a known way. The checker shows pass or fail with evidence per rule."
7. **Same tab.** Point at the UNVERIFIED badge on the FAPI 2.0 pack. Say: "I wrote this rule pack from memory and have not checked it against the specification text."
8. **Flow catalog tab.** Select **DPoP**, click **Simulate** with protection on, then untick **With DPoP** and Simulate again. Say: "Same stolen token, replayed. Without the binding the attack works; with it the proof is missing and the call is refused."
9. **Same tab.** Drag a box, change the Speed, click **Reset**. Say: "Reset puts the diagram back." Mention the other mechanisms: PKCE, PAR, RAR, mTLS, JAR.

## Real mode (owner only, when configured)

Only if the owner set the `TW_REAL*` settings (README "Real mode"); otherwise the Real button is disabled and the "Real not configured" card lists what is needed. This is the hand-off for Customer Agent LAB's UC-LEARN17 (OAuth debug, live token flow log).

10. **Header toggle: Real.** Say: "Now the same tab talks to one real issuer, and nothing else. The banner names it."
11. **Decode / Trace: REAL client_credentials token.** Say: "That is a real access token, labelled REAL, shown raw because this is a debugging tool. Underneath is the trace: the discovery request and the token request exactly as sent and answered. The client secret never appears; it shows as write-only."
12. **Tick Verify, Decode; then Introspect at the issuer.** Say: "Verified against the issuer's real JWKS, then the issuer itself says whether the token is active. The trace shows the requests of the step you just ran."
13. **Profile checker in Real.** Say: "One GET of the issuer's published metadata. A pass here means advertised, not enforced; rules that need crafted attack requests say NOT CHECKED, because we never send those to a real server."
14. **Back to Mock.** Say: "And back to stubs, without a restart."

## If asked: what is honest

- Simulated: the authorization servers, the resource server, the flows, the attacks. The keys and hashes are really computed in memory; nothing is sent over a network.
- UNVERIFIED: the FAPI 2.0 rule pack, and every statement about a specific Ping product. The RFC numbers in the text were not checked against the RFC text.
- Not proven: that any real server behaves like these stubs, that a real product passes or fails these rules, or that the flow catalog is complete. It is a teaching tool, not a certification.

## Likely questions

1. **Does this touch my tenant or a real server?** Not in Mock: the checker accepts only a loopback URL you type. Real is off unless the owner configures one issuer, and then only that issuer's origin is reachable.
2. **Are the tokens real?** In Mock, no: they are minted by a stub, labelled MOCK, and shown raw on purpose for education. In Real they are real tokens from the configured issuer, labelled REAL.
3. **Can I point the checker at a real authorization server?** No, remote targets are refused. Only a local loopback server.
4. **Does a pass here mean my server is compliant?** No. The BCP pack is a simplified check and the FAPI pack is UNVERIFIED.
5. **Why DPoP or mTLS and not just short expiry?** Expiry limits how long a stolen token works; binding stops the thief from using it at all. The catalog shows both sides.

## Reset before the next demo

1. Click **Reset** on the Flow catalog tab and reload the page (clears pasted tokens and results).
2. For a clean state, stop the server and run `npm start` again; stub keys are regenerated in memory.
3. Run `npm run doctor` if the ports look busy (5910 app, 5911-5916 stubs).
