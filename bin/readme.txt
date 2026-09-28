Luau runtime used by the deobfuscator.

  luau.exe / luau-ast.exe   Windows
  luau / luau-ast           Linux (built from the official source)

Both are needed: `luau` runs the sandboxed trace, `luau-ast` dumps the AST
that the VM mapper walks. If a binary for your platform is missing, the tool
downloads the matching official release on first use. On macOS, put a native
`luau` and `luau-ast` here (or on your PATH).
