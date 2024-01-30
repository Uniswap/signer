import {defineConfig} from 'vitest/config';

export default defineConfig({
  test: {
    include: process.env.MANUAL_INTEGRATION_TESTS
      ? ['**/integ/**']
      : ['**/unit/**'],
    watch: false,
    passWithNoTests: true,
    silent: true,
  },
});
