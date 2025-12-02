import baseConfig from '@kitiumai/config/vitest.config.base.js';
import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  ...baseConfig,
  test: {
    ...baseConfig.test,
    globals: true,
    environment: 'node',
    exclude: ['**/node_modules/**', '**/dist/**'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      exclude: ['**/*.test.ts', '**/*.spec.ts', 'dist/**', 'node_modules/**'],
    },
  },
  resolve: {
    alias: {
      '@kitiumai/error': path.resolve(__dirname, '../error/src/index.ts'),
      '@kitiumai/logger': path.resolve(__dirname, '../../../utils/@kitiumai/logger/src/index.ts'),
    },
  },
});
