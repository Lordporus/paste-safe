import { defineConfig } from 'tsup';

export default defineConfig({
  entry: { cli: 'src/cli.ts' },
  format: ['esm'],
  platform: 'node',
  target: 'node20',
  clean: true,
  dts: false,
  sourcemap: false,
  banner: { js: '#!/usr/bin/env node' },
  external: ['commander', 'clipboardy', 'picocolors'],
});
