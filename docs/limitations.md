# Limitations

A clean scan does not prove a server is safe. It means the scanner did not find the problems it knows about.
Here is what it cannot do, so you know where to stay careful.

## Detection

- **Pattern based text checks can be fooled.** Attack text written in new words, another language, or spread
  across many fields may not match. AI review helps, but it is an opinion too.
- **A server can behave differently outside a scan.** It may wait a week, check the hostname, or only attack
  when a certain tool is called with certain input. Dynamic analysis only sees one short session.
- **Only safe tools are called.** Tools that may change things are skipped, so their runtime behavior is not seen.
- **Source analysis is light.** Python is parsed with `ast` and follows tool input through simple assignments
  and local helper functions. JavaScript and TypeScript use line patterns and are less precise. Other languages
  are not analyzed. Compiled or minified code is mostly opaque.
- **Dependency checks are offline.** The known malicious list holds a short set of well known public advisories.
  It is not a full vulnerability database. Use a dependency scanner for that.
- **Typosquat checks only know popular names in the bundled list.**
- **Remote servers are black boxes.** Only their protocol answers can be checked.

## Sandbox

- **The process sandbox is not a security wall.** The server runs as your user. Use Docker for untrusted code.
- **The Docker sandbox cannot see inside the container.** Process and network rules (MCP-DYN-004, -005) only
  work with the process sandbox. File writes to the fake home are still seen.
- **The Docker install step needs the internet.** npx, uvx, and `--run` packages are installed in a separate
  container with the network on. On a slow connection raise `timeouts.install`. The server itself then runs
  without network, so tools that call online APIs answer with errors unless you pass `--network allow` or
  `--network auto`. The report says when tool calls failed only because the sandbox was offline.
- **Without AI, only common install paths are known.** `--run` handles requirements files, Python projects, and
  npm projects. With an AI provider, the AI setup plan handles most other layouts. Repositories that need system
  packages still cannot be installed, because the install container has no root.
- **Static tool lists can be longer than live ones.** For a TypeScript server, the code shows every tool,
  including tools that are only turned on by a flag. chrome-devtools-mcp shows 62 tools in its code and 30 live.
- **Go and Rust tools have no parameter schemas.** Only names and descriptions are read from that code, so
  rules about parameters do not apply. Running the server with `--run` gives the full schemas.
- **A public report from an earlier scan can be old.** It may cover another version than the commit you
  scanned. Its date and version are shown, and it never changes this scan's grade.
- **Minified code is only checked for secrets.** Lines over 500 characters, and files with many of them
  (bundles), are skipped by the code pattern checks. The report lists those files.
- **AI setup plans are not always right.** The AI gets one retry with the error. A wrong plan only fails the
  start. It cannot weaken the sandbox: install steps run in the install container, and the plan cannot change
  `PATH`, `HOME`, or preload libraries.
- **`--network auto` without AI is a guess.** It follows network calls in the source code, which can miss
  calls made by libraries.
- **Servers that need a desktop app or an account** (a video editor, a logged in browser, a cloud API key) start
  and list their tools, but their tool calls fail in the sandbox. Static and listing checks still apply. After two
  tool calls in a row time out, the rest are skipped to save time.
- **Network events are sampled.** The watchdog checks every half second, so a very short connection can be missed.

## Scoring

- The score is a sorting aid. Severity and confidence come from rule authors' judgment.
- Repeated findings of one rule count less, which can hide how many tools share a problem. Read the list.

## Known gaps we plan to improve

- No automatic OSV lookup yet (`scan.online_checks` is reserved for it).
- No full JavaScript parser.
- No Windows Job Object support yet; the process sandbox stops children by walking the process tree.
