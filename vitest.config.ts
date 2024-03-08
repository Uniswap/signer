import {defineConfig} from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**'],
    watch: false,
    passWithNoTests: true,
    silent: true,
  },
});
