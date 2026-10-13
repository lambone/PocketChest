import { Env } from './types';
import { getCurrentTimestamp } from './utils';

// Sessions handled per cron run; the rest wait for the next hourly run. Keeps each run well under the
// per-invocation subrequest limit when there's a backlog.
const CLEANUP_BATCH_SIZE = 50;

// Incomplete sessions are kept until no token can still write to them: the upload token lasts 24h and a
// multipart token created at the end of that lasts another 48h.
const INCOMPLETE_SESSION_TTL_SECONDS = 72 * 60 * 60;

// Delete every R2 object under a prefix, following list() pagination. Throws on failure.
// Abandoned in-progress multipart uploads aren't listed; the bucket's lifecycle rule aborts them after 7 days.
async function deleteR2Prefix(bucket: R2Bucket, prefix: string): Promise<number> {
	let deleted = 0;
	let cursor: string | undefined;
	do {
		const page = await bucket.list({ prefix, cursor });
		if (page.objects.length > 0) {
			await bucket.delete(page.objects.map((obj) => obj.key));
			deleted += page.objects.length;
		}
		cursor = page.truncated ? page.cursor : undefined;
	} while (cursor);
	return deleted;
}

// Cleanup expired content (runs every hour via cron)
export async function cleanupExpiredContent(env: Env): Promise<{
	expiredSessions: number;
	deletedFiles: number;
	r2ObjectsDeleted: number;
	incompleteSessions: number;
	errors: string[];
}> {
	const currentTimestamp = getCurrentTimestamp();
	const errors: string[] = [];
	let expiredSessions = 0;
	let deletedFiles = 0;
	let r2ObjectsDeleted = 0;
	let incompleteSessions = 0;

	console.log('🔍 Starting cleanup for timestamp:', currentTimestamp);

	try {
		// Expired sessions (permanent ones have expiry_date = NULL) and stale incomplete ones, oldest first
		const sessionsResult = await env.DB.prepare(
			`
			SELECT session_id, CASE WHEN upload_complete THEN 'expired' ELSE 'incomplete' END AS reason
			FROM sessions
			WHERE (upload_complete = TRUE AND expiry_date IS NOT NULL AND expiry_date <= ?)
			   OR (upload_complete = FALSE AND created_at <= ?)
			ORDER BY COALESCE(expiry_date, created_at)
			LIMIT ?
		`,
		)
			.bind(currentTimestamp, currentTimestamp - INCOMPLETE_SESSION_TTL_SECONDS, CLEANUP_BATCH_SIZE)
			.all<{ session_id: string; reason: 'expired' | 'incomplete' }>();

		console.log(`🗑️  Sessions to clean up this run: ${sessionsResult.results.length} (max ${CLEANUP_BATCH_SIZE})`);

		for (const { session_id: sessionId, reason } of sessionsResult.results) {
			try {
				// Delete storage first; if it fails, keep the DB rows so the next run retries
				// instead of orphaning the objects
				r2ObjectsDeleted += await deleteR2Prefix(env.R2_STORAGE, `${sessionId}/`);

				const [filesResult] = await env.DB.batch([
					env.DB.prepare(`DELETE FROM files WHERE session_id = ?`).bind(sessionId),
					env.DB.prepare(`DELETE FROM sessions WHERE session_id = ?`).bind(sessionId),
				]);
				const fileCount = filesResult.meta.changes;
				deletedFiles += fileCount;

				if (reason === 'expired') {
					expiredSessions++;
				} else {
					incompleteSessions++;
				}

				console.log(`✅ Cleaned up session ${sessionId} (${reason}) with ${fileCount} files`);
			} catch (error) {
				errors.push(`Failed to cleanup session ${sessionId}: ${error}`);
				console.error(`❌ Error cleaning session ${sessionId}:`, error);
			}
		}

		console.log(
			`🧹 Cleanup summary: ${expiredSessions + incompleteSessions} sessions, ${deletedFiles} files, ${r2ObjectsDeleted} R2 objects`,
		);
	} catch (error) {
		errors.push(`Database query failed: ${error}`);
		console.error('❌ Database error during cleanup:', error);
	}

	return {
		expiredSessions,
		deletedFiles,
		r2ObjectsDeleted,
		incompleteSessions,
		errors,
	};
}
