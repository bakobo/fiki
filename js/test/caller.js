// A caller error, told apart from a bug in fiki (tick 7xbw, T3).
//
// A mistake in the call is a TypeError and never a FikiError (@5zrf8gjk). A bug inside fiki that
// dereferences undefined is a TypeError too, so a test that accepts any TypeError passes on one.
// Each test therefore names a fragment of the message fiki itself writes for that mistake.

import assert from 'node:assert/strict';

import { FikiError } from '../src/index.js';

/** A predicate for assert.throws and assert.rejects: fiki's caller error whose message says `fragment`. */
export const callerError = (fragment) => (err) => {
  assert.ok(err instanceof TypeError, `expected a TypeError, got ${err?.name}: ${err?.message}`);
  assert.ok(!(err instanceof FikiError), `expected no FikiError, got ${err.name}: ${err.message}`);
  assert.ok(err.message.includes(fragment), `expected fiki's message saying "${fragment}", got: ${err.message}`);
  return true;
};
