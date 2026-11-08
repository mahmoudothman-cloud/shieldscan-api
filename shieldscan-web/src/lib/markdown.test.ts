/** Markdown parser: the shapes fix_generation.py emits. */

import { describe, expect, it } from "vitest";
import { parseMarkdown } from "./markdown";

describe("parseMarkdown", () => {
  it("parses headings, fenced code, lists and paragraphs", () => {
    const src = [
      "## Explanation",
      "The `X-Frame-Options` header is **missing**, so the page can be framed.",
      "",
      "## Fix Code",
      "```nginx",
      "add_header X-Frame-Options DENY;",
      "```",
      "## Remediation Steps",
      "1. Add the header",
      "2. Redeploy",
      "- verify with curl",
    ].join("\n");
    expect(parseMarkdown(src)).toEqual([
      { kind: "h", level: 2, text: "Explanation" },
      {
        kind: "p",
        text: "The `X-Frame-Options` header is **missing**, so the page can be framed.",
      },
      { kind: "h", level: 2, text: "Fix Code" },
      { kind: "code", lang: "nginx", text: "add_header X-Frame-Options DENY;" },
      { kind: "h", level: 2, text: "Remediation Steps" },
      { kind: "ol", items: ["Add the header", "Redeploy"] },
      { kind: "ul", items: ["verify with curl"] },
    ]);
  });

  it("keeps an unterminated code fence as code and never emits HTML", () => {
    const blocks = parseMarkdown("```\n<script>alert(1)</script>");
    expect(blocks).toEqual([{ kind: "code", lang: "", text: "<script>alert(1)</script>" }]);
  });
});
