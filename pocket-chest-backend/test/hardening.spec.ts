import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeAll, beforeEach, afterEach } from 'vitest';
import { setupDatabase, setupTestEnvironment, createTestSession, testFetch } from './utils/test-setup';
import worker from '../src/index';

// Covers input validation, completion ordering, multipart lifecycle and size limits

async function uploadSmallFile(sessionId: string, uploadToken: string, content = 'hello') {
	const formData = new FormData();
	formData.append('files', new File([content], 'small.txt', { type: 'text/plain' }));
	const response = await testFetch(`http://example.com/api/chest/${sessionId}/upload`, {
		method: 'POST',
		headers: { Authorization: `Bearer ${uploadToken}` },
		body: formData,
	});
	return response;
}

function complete(sessionId: string, uploadToken: string, body: unknown) {
	return testFetch(`http://example.com/api/chest/${sessionId}/complete`, {
		method: 'POST',
		headers: { Authorization: `Bearer ${uploadToken}`, 'Content-Type': 'application/json' },
		body: JSON.stringify(body),
	});
}

async function createMultipart(sessionId: string, uploadToken: string, fileSize: number) {
	const response = await testFetch(`http://example.com/api/chest/${sessionId}/multipart/create`, {
		method: 'POST',
		headers: { Authorization: `Bearer ${uploadToken}`, 'Content-Type': 'application/json' },
		body: JSON.stringify({ filename: 'big.bin', mimeType: 'application/octet-stream', fileSize }),
	});
	return response;
}

function uploadPart(sessionId: string, fileId: string, token: string, partNumber: string | number, body: BodyInit) {
	return testFetch(`http://example.com/api/chest/${sessionId}/multipart/${fileId}/part/${partNumber}`, {
		method: 'PUT',
		headers: { Authorization: `Bearer ${token}` },
		body,
	});
}

function completeMultipart(sessionId: string, fileId: string, token: string, parts: unknown) {
	return testFetch(`http://example.com/api/chest/${sessionId}/multipart/${fileId}/complete`, {
		method: 'POST',
		headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
		body: JSON.stringify({ parts }),
	});
}

describe('Hardening', () => {
	let sessionId: string;
	let uploadToken: string;

	beforeAll(async () => {
		await setupDatabase();
	});

	beforeEach(async () => {
		await setupTestEnvironment();
		({ sessionId, uploadToken } = await createTestSession());
	});

	afterEach(() => {
		env.MAX_CHEST_BYTES = undefined;
	});

	describe('Completing a chest', () => {
		it('should reject an empty or non-array fileIds with 400', async () => {
			expect((await complete(sessionId, uploadToken, { fileIds: [], validityDays: 7 })).status).toBe(400);
			expect((await complete(sessionId, uploadToken, { fileIds: 'x', validityDays: 7 })).status).toBe(400);
		});

		it('should reject validityDays outside the allowed options', async () => {
			const upload = (await (await uploadSmallFile(sessionId, uploadToken)).json()) as any;
			const fileIds = [upload.uploadedFiles[0].fileId];

			for (const validityDays of [0, -5, 2, 36500, '7', undefined]) {
				const response = await complete(sessionId, uploadToken, { fileIds, validityDays });
				expect(response.status, `validityDays=${validityDays}`).toBe(400);
			}
		});

		it('should leave the session open when validation fails, so a retry succeeds', async () => {
			const upload = (await (await uploadSmallFile(sessionId, uploadToken)).json()) as any;
			const ownFileId = upload.uploadedFiles[0].fileId;

			const other = await createTestSession();
			const otherUpload = (await (await uploadSmallFile(other.sessionId, other.uploadToken)).json()) as any;
			const foreignFileId = otherUpload.uploadedFiles[0].fileId;

			const rejected = await complete(sessionId, uploadToken, { fileIds: [ownFileId, foreignFileId], validityDays: 7 });
			expect(rejected.status).toBe(400);

			const retried = await complete(sessionId, uploadToken, { fileIds: [ownFileId], validityDays: 7 });
			expect(retried.status).toBe(200);
			const data = (await retried.json()) as any;
			expect(data.retrievalCode).toMatch(/^[A-Z0-9]{6}$/);
		});

		it('should accept duplicate file IDs', async () => {
			const upload = (await (await uploadSmallFile(sessionId, uploadToken)).json()) as any;
			const fileId = upload.uploadedFiles[0].fileId;
			expect((await complete(sessionId, uploadToken, { fileIds: [fileId, fileId], validityDays: 1 })).status).toBe(200);
		});
	});

	describe('Multipart uploads', () => {
		it('should reject parts and completion after the chest is completed', async () => {
			const partData = new TextEncoder().encode('late content');
			const create = (await (await createMultipart(sessionId, uploadToken, partData.length)).json()) as any;

			const upload = (await (await uploadSmallFile(sessionId, uploadToken)).json()) as any;
			expect((await complete(sessionId, uploadToken, { fileIds: [upload.uploadedFiles[0].fileId], validityDays: 7 })).status).toBe(200);

			const part = await uploadPart(sessionId, create.fileId, create.uploadId, 1, partData);
			expect(part.status).toBe(404);

			const done = await completeMultipart(sessionId, create.fileId, create.uploadId, [{ partNumber: 1, etag: 'x' }]);
			expect(done.status).toBe(404);
		});

		it('should reject and delete an upload whose real size differs from the declared size', async () => {
			const partData = new TextEncoder().encode('twelve bytes');
			const create = (await (await createMultipart(sessionId, uploadToken, partData.length + 100)).json()) as any;

			const part = (await (await uploadPart(sessionId, create.fileId, create.uploadId, 1, partData)).json()) as any;
			const done = await completeMultipart(sessionId, create.fileId, create.uploadId, [{ partNumber: 1, etag: part.etag }]);

			expect(done.status).toBe(400);
			expect(await env.R2_STORAGE.head(`${sessionId}/${create.fileId}`)).toBeNull();
			const row = await env.DB.prepare('SELECT 1 FROM files WHERE file_id = ?').bind(create.fileId).first();
			expect(row).toBeNull();
		});

		it('should store the real object size', async () => {
			const partData = new TextEncoder().encode('exact size content');
			const create = (await (await createMultipart(sessionId, uploadToken, partData.length)).json()) as any;
			const part = (await (await uploadPart(sessionId, create.fileId, create.uploadId, 1, partData)).json()) as any;
			const done = await completeMultipart(sessionId, create.fileId, create.uploadId, [{ partNumber: 1, etag: part.etag }]);

			expect(done.status).toBe(200);
			const row = await env.DB.prepare('SELECT file_size FROM files WHERE file_id = ?').bind(create.fileId).first<{ file_size: number }>();
			expect(row?.file_size).toBe(partData.length);
		});

		it('should reject a non-numeric part number', async () => {
			const create = (await (await createMultipart(sessionId, uploadToken, 10)).json()) as any;
			expect((await uploadPart(sessionId, create.fileId, create.uploadId, 'abc', 'x')).status).toBe(400);
		});

		it('should reject malformed JSON bodies with 400', async () => {
			const response = await testFetch(`http://example.com/api/chest/${sessionId}/multipart/create`, {
				method: 'POST',
				headers: { Authorization: `Bearer ${uploadToken}`, 'Content-Type': 'application/json' },
				body: 'not json',
			});
			expect(response.status).toBe(400);
		});
	});

	describe('Chest size limit', () => {
		it('should reject a multipart upload that would exceed the limit', async () => {
			env.MAX_CHEST_BYTES = '10';
			expect((await createMultipart(sessionId, uploadToken, 11)).status).toBe(413);
		});

		it('should reject small-file uploads that would exceed the limit', async () => {
			env.MAX_CHEST_BYTES = '10';
			expect((await uploadSmallFile(sessionId, uploadToken, 'eleven char')).status).toBe(413);
			expect((await uploadSmallFile(sessionId, uploadToken, 'ten chars!')).status).toBe(200);
			expect((await uploadSmallFile(sessionId, uploadToken, 'x')).status).toBe(413);
		});
	});

	describe('Error handling', () => {
		it('should reject invalid textItems with 400', async () => {
			for (const textItem of ['{not json', JSON.stringify({ filename: 'a.txt' })]) {
				const formData = new FormData();
				formData.append('textItems', textItem);
				const response = await testFetch(`http://example.com/api/chest/${sessionId}/upload`, {
					method: 'POST',
					headers: { Authorization: `Bearer ${uploadToken}` },
					body: formData,
				});
				expect(response.status, textItem).toBe(400);
			}
		});

		it('should not leak internal error messages', async () => {
			const brokenEnv = {
				...env,
				DB: {
					prepare() {
						throw new Error('SQLITE_ERROR: secret internal detail');
					},
				},
			} as unknown as typeof env;

			const ctx = createExecutionContext();
			const response = await worker.fetch(new Request('http://example.com/api/retrieve/ABC123'), brokenEnv, ctx);
			await waitOnExecutionContext(ctx);

			expect(response.status).toBe(500);
			const body = await response.text();
			expect(body).not.toContain('secret internal detail');
			expect(JSON.parse(body)).toEqual({ error: 'Internal Server Error' });
		});
	});
});
