# Contributing

Zig 0.16 is required, the same version as `minimum_zig_version` in `build.zig.zon`.

```sh
zig fmt --check build.zig src
zig build test
```

`zig fmt` is the formatting standard. Run it on `build.zig` and `src` before sending a change.

Protocol changes belong in `docs/protocol.md` in the same change as the code. The receiver must keep showing the passcode locally, and the listening port must still close after one attempt.

The public API is what `src/root.zig` exports. `0.1.0` can still change; call that out in the pull request when a public declaration changes.
