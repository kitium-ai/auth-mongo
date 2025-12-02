import { defineConfig } from 'vitest/config';
import path from 'node:path';

export default defineConfig({
  test: {
    environment: 'node',
  },
  resolve: {
    alias: {
      '@kitiumai/error': path.resolve(__dirname, 'vitest.mocks/error.ts'),
      '@kitiumai/logger': path.resolve(__dirname, 'vitest.mocks/logger.ts'),
    },
  },
});
