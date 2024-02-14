import {defineConfig} from 'vitest/config';

export default defineConfig({
  test: {
    include: process.env.INTEGRATION_TESTS
      ? ['tests/integ/**']
      : ['tests/unit/**'],
    watch: false,
    passWithNoTests: true,
    silent: true,
  },
});
