import {defineConfig} from 'vitest/config';
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      src: path.resolve(__dirname, 'src'),
    },
  },
  test: {
    include: ['tests/**'],
    watch: false,
    passWithNoTests: true,
    silent: true,
  },
});
