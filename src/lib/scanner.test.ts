// Lightweight runtime test for scanner.ts heuristic coverage.
// Run with: npx tsx src/lib/scanner.test.ts (or via vitest if added later)
//
// Note: this test file does not need a test framework — it uses Node's
// process.exit(1) on failure. CI can run it via `npx tsx src/lib/scanner.test.ts`.
//
// Test strings are constructed dynamically (concatenation) so they do not
// appear as literal secrets in source — GitHub push protection would
// otherwise block the push.

import { scanSkill } from "./scanner";

interface Case {
  name: string;
  line: string;
  shouldMatch: boolean;
}

// Helpers — build a value that matches the regex shape without
// committing a literal secret-looking string to source.
function stripe(s: string, body: string): string {
  return `${s}-${body}`;
}
function join(...parts: string[]): string {
  return parts.join("");
}

const CASES: Case[] = [
  // Stripe (legacy live/test + restricted).
  {
    name: "stripe-live",
    line: join('STRIPE_KEY="', stripe("sk-live", "9f8e7d6c5b4a3210fedcba9876543210"), '"'),
    shouldMatch: true,
  },
  {
    name: "stripe-test",
    line: join('STRIPE_KEY="', stripe("sk-test", "9f8e7d6c5b4a3210fedcba9876543210"), '"'),
    shouldMatch: true,
  },
  {
    name: "stripe-restricted",
    line: join('STRIPE_KEY="rk_live_', "51ABCdefGHIjklMNOpqrsTUVwxyz012345", '"'),
    shouldMatch: true,
  },
  // OpenAI (old sk-... + new sk-proj-... + sk-svcacct-...).
  {
    name: "openai-old",
    line: join('OPENAI_API_KEY="sk-', "abcdefghij1234567890XYZ", '"'),
    shouldMatch: true,
  },
  {
    name: "openai-proj",
    line: join('OPENAI_API_KEY="sk-proj-', "abcdefghijklmnopqrstuvwxyz0123456789ABCDEF", '"'),
    shouldMatch: true,
  },
  {
    name: "openai-svcacct",
    line: join('OPENAI_API_KEY="sk-svcacct-', "abc12345def67890ghi", '"'),
    shouldMatch: true,
  },
  // Anthropic.
  {
    name: "anthropic",
    line: join('ANTHROPIC_API_KEY="sk-ant-api03-', "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", '"'),
    shouldMatch: true,
  },
  // GitHub tokens (PAT, oauth, user-to-server, server-to-server, refresh).
  {
    name: "github-pat",
    line: join('GITHUB_TOKEN="ghp_', "abcdefghijklmnopqrstuvwxyz0123456789ABCD", '"'),
    shouldMatch: true,
  },
  {
    name: "github-oauth",
    line: join('GITHUB_OAUTH="gho_', "abcdefghijklmnopqrstuvwxyz0123456789ABCD", '"'),
    shouldMatch: true,
  },
  // GitLab PAT.
  {
    name: "gitlab-pat",
    line: join('GITLAB_TOKEN="glpat-', "abcdefghijklmnopqrst0123", '"'),
    shouldMatch: true,
  },
  // Slack.
  {
    name: "slack-bot",
    line: join('SLACK_TOKEN="xoxb-', "1234567890-abcdefghij", '"'),
    shouldMatch: true,
  },
  // AWS.
  {
    name: "aws-akia",
    line: join('AWS_ACCESS_KEY_ID="AKIA', "IOSFODNN7EXAMPLE", '"'),
    shouldMatch: true,
  },
  {
    name: "aws-asia",
    line: join('AWS_SESSION_TOKEN="ASIA', "IOSFODNN7EXAMPLE", '"'),
    shouldMatch: true,
  },
  // Google API key.
  {
    name: "google-api",
    line: join('GOOGLE_API_KEY="AIza', "SyD-abcdefghij1234567890_-ABCDEFghij", '"'),
    shouldMatch: true,
  },
  // HuggingFace.
  {
    name: "hf-token",
    line: join('HF_TOKEN="hf_', "abcdefghijklmnopqrstuvwxyz0123456789", '"'),
    shouldMatch: true,
  },
  // npm.
  {
    name: "npm-token",
    line: join('NPM_TOKEN="npm_', "abcdefghijklmnopqrstuvwxyz0123456789AB", '"'),
    shouldMatch: true,
  },
  // SendGrid.
  {
    name: "sendgrid",
    line: join('SENDGRID_API_KEY="SG.', "abcDEFghijklmnop", ".", "ABCdef1234567890abcdefghijklmnopqrstuvwxyz", '"'),
    shouldMatch: true,
  },
  // Twilio Account SID (AC + 32 hex = 34 chars total).
  {
    name: "twilio-sid",
    line: join('TWILIO_SID="AC', "1234567890abcdef1234567890abcdef", '"'),
    shouldMatch: true,
  },
  // PEM private keys (RSA, EC, OPENSSH, DSA, PGP).
  { name: "pem-rsa", line: "-----BEGIN RSA PRIVATE KEY-----", shouldMatch: true },
  { name: "pem-openssh", line: "-----BEGIN OPENSSH PRIVATE KEY-----", shouldMatch: true },
  { name: "pem-pgp", line: "-----BEGIN PGP PRIVATE KEY BLOCK-----", shouldMatch: true },
  // Generic secret-named assignments (with real-looking values).
  { name: "api-key-assign", line: 'api_key: "abcdef0123456789abcdef"', shouldMatch: true },
  { name: "bearer-token-assign", line: 'bearer_token: "secret_0123456789abcdef"', shouldMatch: true },
  { name: "client-secret-assign", line: 'client_secret: "verysecret0123456789"', shouldMatch: true },
  // False-positive guards — these should NOT match (placeholders, examples, low-entropy).
  { name: "your-key-placeholder", line: 'api_key: "your_api_key_here"', shouldMatch: false },
  { name: "angle-bracket-placeholder", line: 'api_key: "<your-key-here>"', shouldMatch: false },
  { name: "repeated-chars", line: 'password: "XXXXXXXXXXXXXXXX"', shouldMatch: false },
  { name: "example-domain", line: 'Visit https://api.example.com for docs.', shouldMatch: false },
  { name: "regular-uuid", line: 'id: "550e8400-e29b-41d4-a716-446655440000"', shouldMatch: false },
];

let failed = 0;
let passed = 0;
for (const c of CASES) {
  const result = scanSkill(c.line, "test.md");
  const hasFinding = result.findings.some((f) => f.id === "hardcoded-secret");
  const ok = hasFinding === c.shouldMatch;
  if (ok) {
    passed++;
  } else {
    failed++;
    console.error(`FAIL: ${c.name}`);
    console.error(`  Input:  ${c.line}`);
    console.error(`  Expected: ${c.shouldMatch ? "match" : "no match"}`);
    console.error(`  Got: ${hasFinding ? "matched" : "no match"}`);
  }
}
console.log(`\n${passed}/${passed + failed} cases passed`);
if (failed > 0) {
  process.exit(1);
}
