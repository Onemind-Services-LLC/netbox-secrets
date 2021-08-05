/**
 * ParcelJS Bundle Configuration.
 *
 * @see https://parceljs.org/api.html
 */

const Bundler = require('parcel-bundler');

// Bundler options common to all bundle jobs.
const options = {
  logLevel: 2,
  cache: true,
  watch: false,
  minify: true,
  outDir: './dist',
  publicUrl: '/static',
};

// Get CLI arguments for optional overrides.
const args = process.argv.slice(2);

// Allow cache disabling.
if (args.includes('--no-cache')) {
  options.cache = false;
}

// Script (JavaScript) bundle jobs. Generally, everything should be bundled into netbox.js from
// index.ts unless there is a specific reason to do otherwise.
const scripts = [['src/index.ts', 'secrets.js']];

/**
 * Run script bundle jobs.
 */
async function bundleScripts() {
  for (const [input, outFile] of scripts) {
    const instance = new Bundler(input, { outFile, ...options });
    await instance.bundle();
  }
}

bundleScripts();
