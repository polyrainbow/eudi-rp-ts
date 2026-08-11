/**
 * Assert what `npm publish` would actually ship.
 *
 * The tarball is the only thing a consumer sees, and its contents come from the
 * `files` glob list in package.json — which is easy to widen by accident and
 * invisible in review when you do. Two things are worth failing a build over:
 *
 *  - `test/fixtures/` holds private keys. They are throwaway and documented as
 *    such in SECURITY.md, but a published package that carries key material
 *    teaches the wrong lesson, and the same slip with real material would look
 *    no different in a diff.
 *  - The package advertises `types` and an `exports` map. A missing
 *    `dist/index.d.ts` breaks every TypeScript consumer at install time, which
 *    is a much worse place to find out than here.
 *
 * Run via `npm run check:package`. Note that `npm pack` triggers `prepack`, so
 * this builds `dist/` if it is stale.
 */
import { execFileSync } from 'node:child_process';

type PackResult = { name: string; version: string; files: { path: string }[] };

/** Files the package promises, by advertising them in package.json. */
const REQUIRED = ['dist/index.js', 'dist/index.d.ts', 'README.md', 'LICENSE', 'NOTICE'];

/**
 * Paths that must never leave the repository.
 *
 * Directory prefixes rather than file names: the point is to catch a `files`
 * entry that pulls in a whole tree, not to enumerate today's key material.
 */
const FORBIDDEN = [
  /^(test|config|out|scripts|app)\//,
  /\.(pem|key|p12|pfx)$/,
  /private|secret/i,
  /\.tsbuildinfo$/,
];

const output = execFileSync('npm', ['pack', '--dry-run', '--json'], { encoding: 'utf8' });
const [pack] = JSON.parse(output) as PackResult[];
if (!pack) throw new Error('npm pack --dry-run --json produced no result');

const paths = pack.files.map((file) => file.path);
const missing = REQUIRED.filter((required) => !paths.includes(required));
const forbidden = paths.filter((path) => FORBIDDEN.some((pattern) => pattern.test(path)));

for (const path of missing) console.error(`MISSING   ${path}`);
for (const path of forbidden) console.error(`FORBIDDEN ${path}`);

if (missing.length > 0 || forbidden.length > 0) {
  console.error(`\n${pack.name}@${pack.version}: ${paths.length} files, tarball rejected`);
  process.exitCode = 1;
} else {
  console.log(`${pack.name}@${pack.version}: ${paths.length} files, nothing unexpected`);
}
