const esbuild = require('esbuild');

// Bundler options common to all bundle jobs.
const options = {
  outdir: './dist',
  bundle: true,
  minify: true,
  sourcemap: true,
  logLevel: 'error',
  publicPath: '/static/netbox_secretstore',
};

/**
 * Run script bundle jobs.
 */
async function bundleScripts() {
  const entryPoints = {
    secrets: 'src/index.ts',
  };
  try {
    let result = await esbuild.build({
      ...options,
      entryPoints,
      target: 'es2016',
    });
    if (result.errors.length === 0) {
      for (const [targetName, sourceName] of Object.entries(entryPoints)) {
        const source = sourceName.split('/')[1];
        console.log(`✅ Bundled source file '${source}' to '${targetName}.js'`);
      }
    }
  } catch (err) {
    console.error(err);
  }
}

bundleScripts();
