import { describe, expect, test } from "vitest";
import { formatShellCommand, splitCommand } from "./command";

describe("desktop command parsing", () => {
  test("keeps quoted shell fragments together", () => {
    expect(splitCommand(`sh -c "printf hi > '/tmp/path with spaces/out.txt'"`)).toEqual([
      "sh",
      "-c",
      "printf hi > '/tmp/path with spaces/out.txt'",
    ]);
  });

  test("handles escaped whitespace and trailing slash literally", () => {
    expect(splitCommand(String.raw`echo path\ with\ spaces \\`)).toEqual([
      "echo",
      "path with spaces",
      "\\",
    ]);
  });

  test("rejects unterminated quotes before invoking backend commands", () => {
    expect(() => splitCommand(`sh -c "unterminated`)).toThrow(
      "unterminated",
    );
  });

  test("renders equivalent CLI with shell-safe quoting", () => {
    expect(
      formatShellCommand([
        "warder",
        "run",
        "--",
        "sh",
        "-c",
        "printf hi > '/tmp/path with spaces/out.txt'",
      ]),
    ).toBe(
      "warder run -- sh -c 'printf hi > '\\''/tmp/path with spaces/out.txt'\\'''",
    );
  });
});
