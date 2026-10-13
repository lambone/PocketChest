import {
	Env,
	CreateChestRequest,
	CreateChestResponse,
	UploadFileResponse,
	CompleteUploadRequest,
	CompleteUploadResponse,
	RetrieveChestResponse,
	CreateMultipartUploadRequest,
	CreateMultipartUploadResponse,
	UploadPartResponse,
	CompleteMultipartUploadRequest,
	CompleteMultipartUploadResponse,
} from './types';
import {
	generateUUID,
	createUploadJWT,
	createChestJWT,
	verifyUploadJWT,
	verifyChestJWT,
	createMultipartJWT,
	verifyMultipartJWT,
	isValidUUID,
	isValidRetrievalCode,
	generateRetrievalCode,
	calculateExpiry,
	getCurrentTimestamp,
	verifyAnyTOTP,
	contentDisposition,
	isValidValidityDays,
	getMaxChestBytes,
} from './utils';
import { cleanupExpiredContent } from './cleanup';

export default {
	async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
		// CORS headers
		const corsHeaders = {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
			'Access-Control-Allow-Headers': 'Content-Type, Authorization',
		};

		// Handle CORS preflight
		if (request.method === 'OPTIONS') {
			return new Response(null, { status: 200, headers: corsHeaders });
		}

		const url = new URL(request.url);
		const path = url.pathname;

		try {
			// Route handling
			if (path === '/api/config' && request.method === 'GET') {
				return await handleGetConfig(env, corsHeaders);
			}

			if (path === '/api/chest' && request.method === 'POST') {
				if (await isRateLimited(env.TOTP_RATE_LIMITER, request)) {
					return tooManyRequests(corsHeaders);
				}
				return await handleCreateChest(request, env, corsHeaders);
			}

			if (path.match(/^\/api\/chest\/[^\/]+\/upload$/) && request.method === 'POST') {
				const sessionId = path.split('/')[3];
				return await handleUploadFiles(request, env, sessionId, corsHeaders);
			}

			// Multipart upload routes
			if (path.match(/^\/api\/chest\/[^\/]+\/multipart\/create$/) && request.method === 'POST') {
				const sessionId = path.split('/')[3];
				return await handleCreateMultipartUpload(request, env, sessionId, corsHeaders);
			}

			if (path.match(/^\/api\/chest\/[^\/]+\/multipart\/[^\/]+\/part\/[^\/]+$/) && request.method === 'PUT') {
				const sessionId = path.split('/')[3];
				const fileId = path.split('/')[5];
				const partNumber = parseInt(path.split('/')[7]);
				return await handleUploadPart(request, env, sessionId, fileId, partNumber, corsHeaders);
			}

			if (path.match(/^\/api\/chest\/[^\/]+\/multipart\/[^\/]+\/complete$/) && request.method === 'POST') {
				const sessionId = path.split('/')[3];
				const fileId = path.split('/')[5];
				return await handleCompleteMultipartUpload(request, env, sessionId, fileId, corsHeaders);
			}

			if (path.match(/^\/api\/chest\/[^\/]+\/complete$/) && request.method === 'POST') {
				const sessionId = path.split('/')[3];
				return await handleCompleteUpload(request, env, sessionId, corsHeaders);
			}

			if (path.match(/^\/api\/retrieve\/[^\/]+$/) && request.method === 'GET') {
				const retrievalCode = path.split('/')[3];
				if (await isRateLimited(env.RETRIEVE_RATE_LIMITER, request)) {
					return tooManyRequests(corsHeaders);
				}
				return await handleRetrieveChest(env, retrievalCode, corsHeaders);
			}

			if (path.match(/^\/api\/download\/[^\/]+$/) && request.method === 'GET') {
				const fileId = path.split('/')[3];
				return await handleDownloadFile(request, env, fileId, corsHeaders);
			}

			return new Response('Not Found', { status: 404, headers: corsHeaders });
		} catch (error) {
			// Log the details, but don't leak internal error text (SQL, stack traces) to clients
			console.error('Error:', error);
			return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
				status: 500,
				headers: { ...corsHeaders, 'Content-Type': 'application/json' },
			});
		}
	},

	// Scheduled event handler (cron job)
	async scheduled(controller: ScheduledController, env: Env, _ctx: ExecutionContext): Promise<void> {
		console.log('🧹 Starting scheduled cleanup job at', new Date().toISOString());

		try {
			const result = await cleanupExpiredContent(env);
			console.log('✅ Cleanup completed successfully:', result);
		} catch (error) {
			console.error('❌ Cleanup job failed:', error);
			// Don't throw - we don't want to fail the cron job
		}
	},
} satisfies ExportedHandler<Env>;

// Per-IP rate limiting for endpoints that accept guessable secrets (TOTP codes, retrieval codes).
// The limiter bindings are optional so local dev and tests work without them.
async function isRateLimited(limiter: RateLimit | undefined, request: Request): Promise<boolean> {
	if (!limiter) return false;
	const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
	const { success } = await limiter.limit({ key: ip });
	return !success;
}

function tooManyRequests(corsHeaders: Record<string, string>): Response {
	return new Response(JSON.stringify({ error: 'Too many requests, please try again later' }), {
		status: 429,
		headers: { ...corsHeaders, 'Content-Type': 'application/json', 'Retry-After': '60' },
	});
}

// Parse a JSON request body, returning null instead of throwing on malformed input
async function readJson<T>(request: Request): Promise<T | null> {
	try {
		return (await request.json()) as T;
	} catch {
		return null;
	}
}

function badRequest(message: string, corsHeaders: Record<string, string>): Response {
	return new Response(message, { status: 400, headers: corsHeaders });
}

function chestTooLarge(maxBytes: number, corsHeaders: Record<string, string>): Response {
	return new Response(`Chest exceeds the maximum size of ${maxBytes} bytes`, { status: 413, headers: corsHeaders });
}

// Uploads are only accepted while the chest is still open (not yet completed)
async function isSessionOpen(env: Env, sessionId: string): Promise<boolean> {
	const session = await env.DB.prepare(`SELECT 1 FROM sessions WHERE session_id = ? AND upload_complete = FALSE`).bind(sessionId).first();
	return session !== null;
}

async function getSessionBytes(env: Env, sessionId: string): Promise<number> {
	const row = await env.DB.prepare(`SELECT COALESCE(SUM(file_size), 0) AS total FROM files WHERE session_id = ?`)
		.bind(sessionId)
		.first<{ total: number }>();
	return row?.total ?? 0;
}

// GET /api/config - Get server configuration
async function handleGetConfig(env: Env, corsHeaders: Record<string, string>): Promise<Response> {
	const config = {
		requireTOTP: env.REQUIRE_TOTP === 'true',
	};

	return new Response(JSON.stringify(config), {
		status: 200,
		headers: { ...corsHeaders, 'Content-Type': 'application/json' },
	});
}

// POST /api/chest - Create new chest
async function handleCreateChest(request: Request, env: Env, corsHeaders: Record<string, string>): Promise<Response> {
	// Check if TOTP is required
	const requireTOTP = env.REQUIRE_TOTP === 'true';

	if (requireTOTP) {
		// Parse request body for TOTP token
		let requestBody: CreateChestRequest;
		try {
			requestBody = await request.json();
		} catch {
			return new Response(JSON.stringify({ error: 'Invalid JSON body' }), {
				status: 400,
				headers: { ...corsHeaders, 'Content-Type': 'application/json' },
			});
		}

		// Validate TOTP token
		if (!requestBody.totpToken) {
			return new Response(JSON.stringify({ error: 'TOTP token required' }), {
				status: 401,
				headers: { ...corsHeaders, 'Content-Type': 'application/json' },
			});
		}

		if (!env.TOTP_SECRETS) {
			return new Response(JSON.stringify({ error: 'TOTP not configured on server' }), {
				status: 500,
				headers: { ...corsHeaders, 'Content-Type': 'application/json' },
			});
		}

		const match = await verifyAnyTOTP(requestBody.totpToken, env.TOTP_SECRETS);
		if (!match) {
			return new Response(JSON.stringify({ error: 'Invalid TOTP token' }), {
				status: 401,
				headers: { ...corsHeaders, 'Content-Type': 'application/json' },
			});
		}

		// Reject replays: each secret's time step can be used once, and never an older one.
		// The conditional upsert is atomic, so two concurrent requests with the same code can't both succeed.
		const claim = await env.DB.prepare(
			`
			INSERT INTO totp_used (secret_name, last_step) VALUES (?, ?)
			ON CONFLICT(secret_name) DO UPDATE SET last_step = excluded.last_step
			WHERE excluded.last_step > totp_used.last_step
		`,
		)
			.bind(match.name, match.timeStep)
			.run();
		if (claim.meta.changes !== 1) {
			return new Response(JSON.stringify({ error: 'TOTP token already used, wait for the next code' }), {
				status: 401,
				headers: { ...corsHeaders, 'Content-Type': 'application/json' },
			});
		}
	}

	// Generate session ID
	const sessionId = generateUUID();

	// Create upload JWT
	const uploadToken = await createUploadJWT(sessionId, env.JWT_SECRET);

	// Insert session into database
	await env.DB.prepare(
		`
		INSERT INTO sessions (session_id, created_at, updated_at)
		VALUES (?, ?, ?)
	`,
	)
		.bind(sessionId, getCurrentTimestamp(), getCurrentTimestamp())
		.run();

	const response: CreateChestResponse = {
		sessionId,
		uploadToken,
		expiresIn: 86400, // 24 hours
	};

	return new Response(JSON.stringify(response), {
		status: 200,
		headers: { ...corsHeaders, 'Content-Type': 'application/json' },
	});
}

// POST /api/chest/:sessionId/upload - Upload files
async function handleUploadFiles(request: Request, env: Env, sessionId: string, corsHeaders: Record<string, string>): Promise<Response> {
	// Verify JWT token
	const authHeader = request.headers.get('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		return new Response('Unauthorized', { status: 401, headers: corsHeaders });
	}

	const token = authHeader.substring(7);
	let payload;
	try {
		payload = await verifyUploadJWT(token, env.JWT_SECRET);
	} catch (_error) {
		return new Response('Invalid token', { status: 401, headers: corsHeaders });
	}

	// Validate sessionId matches JWT and URL param
	if (payload.sessionId !== sessionId || !isValidUUID(sessionId)) {
		return new Response('Invalid session', { status: 400, headers: corsHeaders });
	}

	// Check session exists and is not completed
	const session = await env.DB.prepare(
		`
		SELECT * FROM sessions WHERE session_id = ? AND upload_complete = FALSE
	`,
	)
		.bind(sessionId)
		.first();

	if (!session) {
		return new Response('Session not found or already completed', { status: 404, headers: corsHeaders });
	}

	// Parse multipart form data
	let formData: FormData;
	try {
		formData = await request.formData();
	} catch {
		return badRequest('Invalid form data', corsHeaders);
	}

	// Validate everything before writing to storage, so a bad item doesn't leave partial uploads behind
	type PendingItem = { body: ReadableStream | string; filename: string; mimeType: string; size: number; isText: boolean };
	const items: PendingItem[] = [];

	for (const [key, value] of formData.entries()) {
		if (key === 'files' && value instanceof File) {
			items.push({
				body: value.stream(),
				filename: value.name || 'unnamed-file',
				mimeType: value.type || 'application/octet-stream',
				size: value.size,
				isText: false,
			});
		}
	}

	for (const textItem of formData.getAll('textItems')) {
		if (typeof textItem !== 'string') continue;
		let textData: { content?: unknown; filename?: unknown };
		try {
			textData = JSON.parse(textItem);
		} catch {
			return badRequest('Invalid textItems JSON', corsHeaders);
		}
		if (typeof textData?.content !== 'string') {
			return badRequest('Each text item needs a string content field', corsHeaders);
		}
		items.push({
			body: textData.content,
			filename: typeof textData.filename === 'string' && textData.filename ? textData.filename : `text-${Date.now()}.txt`,
			mimeType: 'text/plain',
			size: new TextEncoder().encode(textData.content).length,
			isText: true,
		});
	}

	const maxBytes = getMaxChestBytes(env.MAX_CHEST_BYTES);
	const incomingBytes = items.reduce((sum, item) => sum + item.size, 0);
	if ((await getSessionBytes(env, sessionId)) + incomingBytes > maxBytes) {
		return chestTooLarge(maxBytes, corsHeaders);
	}

	const uploadedFiles: Array<{ fileId: string; filename: string; isText: boolean }> = [];
	const fileInserts: D1PreparedStatement[] = [];
	const r2Operations: Promise<R2Object | null>[] = [];
	const timestamp = getCurrentTimestamp();

	for (const item of items) {
		const fileId = generateUUID();
		r2Operations.push(env.R2_STORAGE.put(`${sessionId}/${fileId}`, item.body));
		fileInserts.push(
			env.DB.prepare(
				`
				INSERT INTO files (file_id, session_id, original_filename, mime_type, file_size, file_extension, is_text, created_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			`,
			).bind(fileId, sessionId, item.filename, item.mimeType, item.size, getFileExtension(item.filename), item.isText, timestamp),
		);
		uploadedFiles.push({ fileId, filename: item.filename, isText: item.isText });
	}

	// Execute all operations in parallel: R2 storage + database batch
	const [_r2Results, dbResult] = await Promise.all([
		Promise.all(r2Operations),
		fileInserts.length > 0 ? env.DB.batch(fileInserts) : Promise.resolve([]),
	]);

	// Verify all database operations succeeded
	if (fileInserts.length > 0) {
		const failedInserts = dbResult.filter((result) => !result.success);
		if (failedInserts.length > 0) {
			throw new Error(`Failed to insert ${failedInserts.length} file records`);
		}
	}

	const response: UploadFileResponse = { uploadedFiles };
	return new Response(JSON.stringify(response), {
		status: 200,
		headers: { ...corsHeaders, 'Content-Type': 'application/json' },
	});
}

// POST /api/chest/:sessionId/complete - Complete upload and generate retrieval code
async function handleCompleteUpload(request: Request, env: Env, sessionId: string, corsHeaders: Record<string, string>): Promise<Response> {
	// Verify JWT token
	const authHeader = request.headers.get('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		return new Response('Unauthorized', { status: 401, headers: corsHeaders });
	}

	const token = authHeader.substring(7);
	let payload;
	try {
		payload = await verifyUploadJWT(token, env.JWT_SECRET);
	} catch (_error) {
		return new Response('Invalid token', { status: 401, headers: corsHeaders });
	}

	if (payload.sessionId !== sessionId || !isValidUUID(sessionId)) {
		return new Response('Invalid session', { status: 400, headers: corsHeaders });
	}

	// Parse and validate request body
	const body = await readJson<CompleteUploadRequest>(request);
	if (!body) {
		return badRequest('Invalid JSON body', corsHeaders);
	}
	const { fileIds, validityDays } = body;

	if (!Array.isArray(fileIds) || fileIds.length === 0) {
		return badRequest('fileIds must be a non-empty array', corsHeaders);
	}
	if (!fileIds.every((fileId) => typeof fileId === 'string' && isValidUUID(fileId))) {
		return badRequest('Invalid file ID format', corsHeaders);
	}
	if (!isValidValidityDays(validityDays)) {
		return badRequest('validityDays must be one of 1, 3, 7, 15, or -1 (permanent)', corsHeaders);
	}
	const uniqueFileIds = [...new Set(fileIds)];

	// Validate before changing anything, so a rejected request leaves the session open to retry
	const ownedFiles = await env.DB.prepare(
		`
		SELECT COUNT(*) as count FROM files
		WHERE file_id IN (${uniqueFileIds.map(() => '?').join(',')}) AND session_id = ?
	`,
	)
		.bind(...uniqueFileIds, sessionId)
		.first<{ count: number }>();

	if (ownedFiles?.count !== uniqueFileIds.length) {
		return badRequest('Some files do not belong to this session', corsHeaders);
	}

	const expiryDate = calculateExpiry(validityDays);
	const timestamp = getCurrentTimestamp();

	// retrieval_code is UNIQUE, so a collision fails the UPDATE; retry with a fresh code
	for (let attempt = 0; attempt < 5; attempt++) {
		const retrievalCode = generateRetrievalCode();
		let changes: number;
		try {
			const result = await env.DB.prepare(
				`
				UPDATE sessions
				SET retrieval_code = ?, upload_complete = TRUE, expiry_date = ?, updated_at = ?
				WHERE session_id = ? AND upload_complete = FALSE
			`,
			)
				.bind(retrievalCode, expiryDate, timestamp, sessionId)
				.run();
			changes = result.meta.changes;
		} catch (error) {
			if (String(error).includes('UNIQUE')) continue;
			throw error;
		}

		if (changes === 0) {
			return new Response('Session not found or already completed', { status: 404, headers: corsHeaders });
		}

		const response: CompleteUploadResponse = {
			retrievalCode,
			expiryDate: expiryDate ? new Date(expiryDate * 1000).toISOString() : null,
		};

		return new Response(JSON.stringify(response), {
			status: 200,
			headers: { ...corsHeaders, 'Content-Type': 'application/json' },
		});
	}

	return new Response('Failed to generate unique retrieval code', { status: 500, headers: corsHeaders });
}

// GET /api/retrieve/:retrievalCode - Get chest contents
async function handleRetrieveChest(env: Env, retrievalCode: string, corsHeaders: Record<string, string>): Promise<Response> {
	if (!isValidRetrievalCode(retrievalCode)) {
		return new Response('Invalid retrieval code format', { status: 400, headers: corsHeaders });
	}

	// Find session by retrieval code
	const session = await env.DB.prepare(
		`
		SELECT * FROM sessions 
		WHERE retrieval_code = ? AND upload_complete = TRUE 
		AND (expiry_date IS NULL OR expiry_date > ?)
	`,
	)
		.bind(retrievalCode, getCurrentTimestamp())
		.first();

	if (!session) {
		return new Response('Retrieval code not found or expired', { status: 404, headers: corsHeaders });
	}

	// Get all files for this session
	const files = await env.DB.prepare(
		`
		SELECT * FROM files WHERE session_id = ? ORDER BY created_at
	`,
	)
		.bind(session.session_id)
		.all();

	// Create chest JWT
	const chestToken = await createChestJWT(session.session_id as string, session.expiry_date as number | null, env.JWT_SECRET);

	const response: RetrieveChestResponse = {
		files: files.results.map((file) => ({
			fileId: file.file_id as string,
			filename: file.original_filename as string,
			size: file.file_size as number,
			mimeType: file.mime_type as string,
			isText: Boolean(file.is_text),
			fileExtension: file.file_extension as string | null,
		})),
		chestToken,
		expiryDate: session.expiry_date ? new Date((session.expiry_date as number) * 1000).toISOString() : null,
	};

	return new Response(JSON.stringify(response), {
		status: 200,
		headers: { ...corsHeaders, 'Content-Type': 'application/json' },
	});
}

// GET /api/download/:fileId - Download file
async function handleDownloadFile(request: Request, env: Env, fileId: string, corsHeaders: Record<string, string>): Promise<Response> {
	// Extract token from header or query parameter
	const url = new URL(request.url);
	const authHeader = request.headers.get('Authorization');
	const tokenFromQuery = url.searchParams.get('token');
	const filenameFromQuery = url.searchParams.get('filename');

	let token: string;
	if (authHeader && authHeader.startsWith('Bearer ')) {
		token = authHeader.substring(7);
	} else if (tokenFromQuery) {
		token = tokenFromQuery;
	} else {
		return new Response('Unauthorized', { status: 401, headers: corsHeaders });
	}

	let payload;
	try {
		payload = await verifyChestJWT(token, env.JWT_SECRET);
	} catch (_error) {
		return new Response('Invalid token', { status: 401, headers: corsHeaders });
	}

	if (!isValidUUID(fileId)) {
		return new Response('Invalid file ID format', { status: 400, headers: corsHeaders });
	}

	// Get file metadata and verify session is still valid
	const fileWithSession = await env.DB.prepare(
		`
		SELECT f.*, s.expiry_date
		FROM files f
		JOIN sessions s ON f.session_id = s.session_id
		WHERE f.file_id = ? AND f.session_id = ?
		AND (s.expiry_date IS NULL OR s.expiry_date > ?)
	`,
	)
		.bind(fileId, payload.sessionId, getCurrentTimestamp())
		.first();

	if (!fileWithSession) {
		return new Response('File not found or session expired', { status: 404, headers: corsHeaders });
	}

	// Get file from R2
	const r2Object = await env.R2_STORAGE.get(`${payload.sessionId}/${fileId}`);
	if (!r2Object) {
		return new Response('File not found in storage', { status: 404, headers: corsHeaders });
	}

	// Use filename from query parameter if provided, otherwise use original filename
	const downloadFilename = filenameFromQuery || (fileWithSession.original_filename as string);

	// Return file with proper headers
	return new Response(r2Object.body, {
		status: 200,
		headers: {
			...corsHeaders,
			'Content-Type': fileWithSession.mime_type as string,
			'Content-Disposition': contentDisposition(downloadFilename),
			'Content-Length': String(fileWithSession.file_size),
		},
	});
}

// Helper function to get file extension
function getFileExtension(filename: string): string | null {
	const lastDot = filename.lastIndexOf('.');
	return lastDot > 0 ? filename.substring(lastDot + 1) : null;
}

// POST /api/chest/:sessionId/multipart/create - Create multipart upload
async function handleCreateMultipartUpload(
	request: Request,
	env: Env,
	sessionId: string,
	corsHeaders: Record<string, string>,
): Promise<Response> {
	// Verify JWT token
	const authHeader = request.headers.get('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		return new Response('Unauthorized', { status: 401, headers: corsHeaders });
	}

	const token = authHeader.substring(7);
	let payload;
	try {
		payload = await verifyUploadJWT(token, env.JWT_SECRET);
	} catch (_error) {
		return new Response('Invalid token', { status: 401, headers: corsHeaders });
	}

	// Validate sessionId matches JWT and URL param
	if (payload.sessionId !== sessionId || !isValidUUID(sessionId)) {
		return new Response('Invalid session', { status: 400, headers: corsHeaders });
	}

	// Check session exists and is not completed
	const session = await env.DB.prepare(
		`
		SELECT * FROM sessions WHERE session_id = ? AND upload_complete = FALSE
	`,
	)
		.bind(sessionId)
		.first();

	if (!session) {
		return new Response('Session not found or already completed', { status: 404, headers: corsHeaders });
	}

	// Parse request body
	const body = await readJson<CreateMultipartUploadRequest>(request);
	if (!body) {
		return badRequest('Invalid JSON body', corsHeaders);
	}
	const { filename, mimeType, fileSize } = body;

	// Validate inputs
	if (
		typeof filename !== 'string' ||
		!filename ||
		typeof mimeType !== 'string' ||
		!mimeType ||
		!Number.isSafeInteger(fileSize) ||
		fileSize <= 0
	) {
		return badRequest('Invalid multipart upload parameters', corsHeaders);
	}

	// The declared size is checked here and enforced against the real object size on completion
	const maxBytes = getMaxChestBytes(env.MAX_CHEST_BYTES);
	if ((await getSessionBytes(env, sessionId)) + fileSize > maxBytes) {
		return chestTooLarge(maxBytes, corsHeaders);
	}

	const fileId = generateUUID();

	// Create multipart upload in R2
	const multipartUpload = await env.R2_STORAGE.createMultipartUpload(`${sessionId}/${fileId}`);

	// Create multipart JWT with 48-hour validity
	const multipartToken = await createMultipartJWT(
		sessionId,
		fileId,
		multipartUpload.uploadId,
		filename,
		mimeType,
		fileSize,
		env.JWT_SECRET,
	);

	const response: CreateMultipartUploadResponse = {
		fileId,
		uploadId: multipartToken, // Return JWT instead of raw uploadId
	};

	return new Response(JSON.stringify(response), {
		status: 200,
		headers: { ...corsHeaders, 'Content-Type': 'application/json' },
	});
}

// PUT /api/chest/:sessionId/multipart/:fileId/part/:partNumber - Upload part
async function handleUploadPart(
	request: Request,
	env: Env,
	sessionId: string,
	fileId: string,
	partNumber: number,
	corsHeaders: Record<string, string>,
): Promise<Response> {
	// Verify multipart JWT token from header
	const authHeader = request.headers.get('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		return new Response('Unauthorized', { status: 401, headers: corsHeaders });
	}

	const token = authHeader.substring(7);
	let payload;
	try {
		payload = await verifyMultipartJWT(token, env.JWT_SECRET);
	} catch (_error) {
		return new Response('Invalid multipart token', { status: 401, headers: corsHeaders });
	}

	// Validate sessionId and fileId match JWT and URL params
	if (payload.sessionId !== sessionId || payload.fileId !== fileId) {
		return new Response('Token does not match upload session', { status: 403, headers: corsHeaders });
	}

	if (!isValidUUID(sessionId) || !isValidUUID(fileId)) {
		return new Response('Invalid session or file ID format', { status: 400, headers: corsHeaders });
	}

	// Validate part number (parseInt gives NaN for non-numeric input)
	if (!Number.isInteger(partNumber) || partNumber < 1 || partNumber > 10000) {
		return badRequest('Invalid part number', corsHeaders);
	}

	// A multipart token outlives chest completion, so check the chest is still open
	if (!(await isSessionOpen(env, sessionId))) {
		return new Response('Session not found or already completed', { status: 404, headers: corsHeaders });
	}

	// Get request body as ArrayBuffer
	const body = await request.arrayBuffer();
	if (!body || body.byteLength === 0) {
		return badRequest('Empty part body', corsHeaders);
	}
	if (body.byteLength > payload.fileSize) {
		return badRequest('Part is larger than the declared file size', corsHeaders);
	}

	// Resume multipart upload using uploadId from JWT
	const multipartUpload = env.R2_STORAGE.resumeMultipartUpload(`${sessionId}/${fileId}`, payload.uploadId);
	const uploadedPart = await multipartUpload.uploadPart(partNumber, body);

	const response: UploadPartResponse = {
		etag: uploadedPart.etag,
		partNumber,
	};

	return new Response(JSON.stringify(response), {
		status: 200,
		headers: { ...corsHeaders, 'Content-Type': 'application/json' },
	});
}

// POST /api/chest/:sessionId/multipart/:fileId/complete - Complete multipart upload
async function handleCompleteMultipartUpload(
	request: Request,
	env: Env,
	sessionId: string,
	fileId: string,
	corsHeaders: Record<string, string>,
): Promise<Response> {
	// Verify multipart JWT token
	const authHeader = request.headers.get('Authorization');
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		return new Response('Unauthorized', { status: 401, headers: corsHeaders });
	}

	const token = authHeader.substring(7);
	let payload;
	try {
		payload = await verifyMultipartJWT(token, env.JWT_SECRET);
	} catch (_error) {
		return new Response('Invalid multipart token', { status: 401, headers: corsHeaders });
	}

	// Validate sessionId and fileId match JWT and URL params
	if (payload.sessionId !== sessionId || payload.fileId !== fileId) {
		return new Response('Token does not match upload session', { status: 403, headers: corsHeaders });
	}

	if (!isValidUUID(sessionId) || !isValidUUID(fileId)) {
		return new Response('Invalid session or file ID format', { status: 400, headers: corsHeaders });
	}

	// A multipart token outlives chest completion, so check the chest is still open
	if (!(await isSessionOpen(env, sessionId))) {
		return new Response('Session not found or already completed', { status: 404, headers: corsHeaders });
	}

	// Parse request body
	const body = await readJson<CompleteMultipartUploadRequest>(request);
	if (!body) {
		return badRequest('Invalid JSON body', corsHeaders);
	}
	const { parts } = body;

	// Validate parts array
	if (
		!Array.isArray(parts) ||
		parts.length === 0 ||
		!parts.every((part) => Number.isInteger(part?.partNumber) && typeof part?.etag === 'string')
	) {
		return badRequest('Invalid parts array', corsHeaders);
	}

	// Sort parts by part number to ensure correct order
	const sortedParts = parts.sort((a, b) => a.partNumber - b.partNumber);

	// Resume multipart upload and complete it using uploadId from JWT
	const key = `${sessionId}/${fileId}`;
	const multipartUpload = env.R2_STORAGE.resumeMultipartUpload(key, payload.uploadId);
	const object = await multipartUpload.complete(sortedParts);

	// Trust the assembled object's real size, not the size the client declared
	if (object.size !== payload.fileSize) {
		await env.R2_STORAGE.delete(key);
		return badRequest('Uploaded size does not match the declared file size', corsHeaders);
	}
	const maxBytes = getMaxChestBytes(env.MAX_CHEST_BYTES);
	if ((await getSessionBytes(env, sessionId)) + object.size > maxBytes) {
		await env.R2_STORAGE.delete(key);
		return chestTooLarge(maxBytes, corsHeaders);
	}

	// Now insert the file record into database (only after successful completion)
	const timestamp = getCurrentTimestamp();
	await env.DB.prepare(
		`
		INSERT INTO files (file_id, session_id, original_filename, mime_type, file_size, file_extension, is_text, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
	)
		.bind(fileId, sessionId, payload.filename, payload.mimeType, object.size, getFileExtension(payload.filename), false, timestamp)
		.run();

	const response: CompleteMultipartUploadResponse = {
		fileId,
		filename: payload.filename,
	};

	return new Response(JSON.stringify(response), {
		status: 200,
		headers: { ...corsHeaders, 'Content-Type': 'application/json' },
	});
}
