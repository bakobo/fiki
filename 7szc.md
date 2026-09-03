# fiki cannot know about a body it was never given. The @2hwvpm42 guarantee is 'if you hand fiki the body, it is covered or fiki refuses' — a caller who simply omits body= gets a signature over a request whose body is unprotected, and fiki has no way to detect that. The honest scope belongs in the README and the sign_request docstring rather than being left for a reader to discover. Consider whether an integration adapter (httpx, requests) should be the answer, since an adapter sees the real request object and cannot be handed a partial one
kind: todo
created: 2026-09-03T23:48Z

