export function splitCommand(input: string): string[] {
  const args: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  let escaped = false;

  for (const char of input) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (quote) {
      if (char === quote) {
        quote = null;
      } else {
        current += char;
      }
      continue;
    }
    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }
    if (/\s/.test(char)) {
      if (current) {
        args.push(current);
        current = "";
      }
      continue;
    }
    current += char;
  }

  if (escaped) {
    current += "\\";
  }
  if (quote) {
    throw new Error(`unterminated ${quote} quote in command`);
  }
  if (current) {
    args.push(current);
  }
  return args;
}

export function formatShellCommand(args: string[]): string {
  return args.map(shellQuote).join(" ");
}

function shellQuote(value: string): string {
  if (value === "") {
    return "''";
  }
  if (/^[A-Za-z0-9_./:=+@%-]+$/.test(value)) {
    return value;
  }
  return `'${value.split("'").join("'\\''")}'`;
}
