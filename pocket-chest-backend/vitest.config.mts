import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

export default defineConfig({
	plugins: [
		cloudflareTest({
			wrangler: { configPath: './wrangler.jsonc' },
			miniflare: {
				// Default test environment variables - can be overridden in individual tests
				vars: {
					REQUIRE_TOTP: 'false',
					JWT_SECRET: 'test-jwt-secret-for-vitest-only',
				},
			},
		}),
	],
	test: {},
});
