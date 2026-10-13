import { env } from 'cloudflare:test';
import { describe, it, expect, beforeAll, beforeEach } from 'vitest';
import { setupDatabase, setupTestEnvironment } from './utils/test-setup';
import { cleanupExpiredContent } from '../src/cleanup';
import { generateUUID, getCurrentTimestamp } from '../src/utils';

const HOUR = 60 * 60;

async function insertSession(opts: { complete: boolean; createdAt: number; expiryDate: number | null }): Promise<string> {
	const sessionId = generateUUID();
	await env.DB.prepare(
		`INSERT INTO sessions (session_id, retrieval_code, upload_complete, expiry_date, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
	)
		.bind(
			sessionId,
			opts.complete ? sessionId.slice(0, 6).toUpperCase() : null,
			opts.complete,
			opts.expiryDate,
			opts.createdAt,
			opts.createdAt,
		)
		.run();
	return sessionId;
}

async function insertFile(sessionId: string): Promise<string> {
	const fileId = generateUUID();
	await env.R2_STORAGE.put(`${sessionId}/${fileId}`, 'content');
	await env.DB.prepare(
		`INSERT INTO files (file_id, session_id, original_filename, mime_type, file_size, is_text) VALUES (?, ?, 'f.txt', 'text/plain', 7, FALSE)`,
	)
		.bind(fileId, sessionId)
		.run();
	return fileId;
}

async function sessionExists(sessionId: string): Promise<boolean> {
	return (await env.DB.prepare('SELECT 1 FROM sessions WHERE session_id = ?').bind(sessionId).first()) !== null;
}

describe('Scheduled cleanup', () => {
	beforeAll(async () => {
		await setupDatabase();
	});

	beforeEach(async () => {
		await setupTestEnvironment();
	});

	it('should delete expired sessions with their files and storage, and keep live and permanent ones', async () => {
		const now = getCurrentTimestamp();
		const expired = await insertSession({ complete: true, createdAt: now - 10 * HOUR, expiryDate: now - HOUR });
		const live = await insertSession({ complete: true, createdAt: now - 10 * HOUR, expiryDate: now + HOUR });
		const permanent = await insertSession({ complete: true, createdAt: now - 1000 * HOUR, expiryDate: null });
		const expiredFile = await insertFile(expired);
		await insertFile(live);

		const result = await cleanupExpiredContent(env);

		expect(result.errors).toEqual([]);
		expect(result.expiredSessions).toBe(1);
		expect(await sessionExists(expired)).toBe(false);
		expect(await sessionExists(live)).toBe(true);
		expect(await sessionExists(permanent)).toBe(true);
		expect(await env.R2_STORAGE.head(`${expired}/${expiredFile}`)).toBeNull();
	});

	it('should delete every stored object of a session, past the first list page', async () => {
		const now = getCurrentTimestamp();
		const sessionId = await insertSession({ complete: true, createdAt: now - 10 * HOUR, expiryDate: now - HOUR });
		const keys = Array.from({ length: 1005 }, (_, i) => `${sessionId}/obj-${String(i).padStart(4, '0')}`);
		for (let i = 0; i < keys.length; i += 100) {
			await Promise.all(keys.slice(i, i + 100).map((key) => env.R2_STORAGE.put(key, 'x')));
		}

		const result = await cleanupExpiredContent(env);

		expect(result.r2ObjectsDeleted).toBe(1005);
		expect((await env.R2_STORAGE.list({ prefix: `${sessionId}/` })).objects).toHaveLength(0);
	});

	it('should keep incomplete sessions until no upload token can still write to them (72h)', async () => {
		const now = getCurrentTimestamp();
		const recent = await insertSession({ complete: false, createdAt: now - 49 * HOUR, expiryDate: null });
		const stale = await insertSession({ complete: false, createdAt: now - 73 * HOUR, expiryDate: null });

		const result = await cleanupExpiredContent(env);

		expect(result.incompleteSessions).toBe(1);
		expect(await sessionExists(recent)).toBe(true);
		expect(await sessionExists(stale)).toBe(false);
	});

	it('should process at most 50 sessions per run', async () => {
		const now = getCurrentTimestamp();
		for (let i = 0; i < 55; i++) {
			await insertSession({ complete: true, createdAt: now - 10 * HOUR, expiryDate: now - HOUR - i });
		}

		const first = await cleanupExpiredContent(env);
		expect(first.expiredSessions).toBe(50);

		const second = await cleanupExpiredContent(env);
		expect(second.expiredSessions).toBe(5);
	});

	it('should keep the database rows when storage deletion fails, so the next run retries', async () => {
		const now = getCurrentTimestamp();
		const sessionId = await insertSession({ complete: true, createdAt: now - 10 * HOUR, expiryDate: now - HOUR });
		await insertFile(sessionId);

		const failingStorage = {
			list() {
				throw new Error('R2 unavailable');
			},
		} as unknown as R2Bucket;
		const result = await cleanupExpiredContent({ ...env, R2_STORAGE: failingStorage } as typeof env);

		expect(result.errors).toHaveLength(1);
		expect(await sessionExists(sessionId)).toBe(true);
		const files = await env.DB.prepare('SELECT COUNT(*) AS n FROM files WHERE session_id = ?').bind(sessionId).first<{ n: number }>();
		expect(files?.n).toBe(1);
	});
});
