# fiki-js ships no TypeScript declarations (review DX-F1, bakobo/reviews fiki/2026-10-09-pre-0.9.0-dx/dev-experience-pre-0.9.0-dx.md): no .d.ts, no 'types' in package.json, so a TypeScript caller gets any for every import and no check on signRequest/verifyRequest's named-parameter shapes, including the required authorities and expectedKeyid decisions. Deferred from 0.9.0 on 2026-10-09 because it is additive and needs a decision on how the declarations stay true: hand-written .d.ts checked by a tsd/expect-type test, or JSDoc types emitted with tsc --allowJs --declaration in the release build. Either way a test must fail when the declarations drift from the code.
kind: todo
created: 2026-10-09T21:02Z

