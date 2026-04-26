import { defineConfig } from 'vitest/config';
import { resolve } from 'path';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['**/*.test.ts', '**/*.spec.ts'],
    exclude: ['node_modules', 'dist'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'dist/',
        '**/*.test.ts',
        '**/*.spec.ts',
        '**/types/',
      ],
    },
  },
  resolve: {
    alias: {
      '@sentinel/schemas': resolve(__dirname, 'packages/schemas/src'),
      '@sentinel/logger': resolve(__dirname, 'packages/logger/src'),
      '@sentinel/cache': resolve(__dirname, 'packages/cache/src'),
      '@sentinel/ip-reputation': resolve(__dirname, 'packages/ip-reputation/src'),
      '@sentinel/pipeline': resolve(__dirname, 'packages/pipeline/src'),
      '@sentinel/agents': resolve(__dirname, 'packages/agents/src'),
    },
  },
});