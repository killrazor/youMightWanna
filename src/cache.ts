import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import { DEFAULT_THROTTLE, THROTTLE_BOUNDS, type ThrottleState } from './types.js';

const THROTTLE_STATE_KEY = 'cache/throttle-state.json';

// S3 client - uses default credential chain (env vars, IAM role, etc.)
let s3Client: S3Client | null = null;
let bucketName: string | null = null;

export function initS3Cache(bucket: string, region = 'us-east-1'): void {
  bucketName = bucket;
  s3Client = new S3Client({ region });
  console.log(`      S3 cache initialized: s3://${bucket}/`);
}

export function isCacheEnabled(): boolean {
  return s3Client !== null && bucketName !== null;
}

async function getObject<T>(key: string): Promise<T | null> {
  if (!s3Client || !bucketName) return null;

  try {
    const response = await s3Client.send(
      new GetObjectCommand({ Bucket: bucketName, Key: key })
    );
    const body = await response.Body?.transformToString();
    return body ? JSON.parse(body) : null;
  } catch (err: unknown) {
    // NoSuchKey is expected for first run
    if ((err as { name?: string }).name === 'NoSuchKey') {
      return null;
    }
    console.warn(`      Warning: Failed to read ${key} from S3:`, (err as Error).message);
    return null;
  }
}

async function putObject<T>(key: string, data: T): Promise<boolean> {
  if (!s3Client || !bucketName) return false;

  try {
    await s3Client.send(
      new PutObjectCommand({
        Bucket: bucketName,
        Key: key,
        Body: JSON.stringify(data, null, 2),
        ContentType: 'application/json',
      })
    );
    return true;
  } catch (err) {
    console.warn(`      Warning: Failed to write ${key} to S3:`, (err as Error).message);
    return false;
  }
}

// Load throttle state from S3, or return defaults
// Only concurrency is actively used now - rate limiting is handled by sliding window in nvd.ts
export async function loadThrottleState(): Promise<ThrottleState> {
  const state = await getObject<ThrottleState>(THROTTLE_STATE_KEY);
  if (state) {
    // Clamp concurrency to bounds (don't reset entirely, just adjust)
    if (state.concurrency > THROTTLE_BOUNDS.max_concurrency) {
      console.log(`      Cached throttle has concurrency=${state.concurrency}, clamping to max=${THROTTLE_BOUNDS.max_concurrency}`);
      state.concurrency = THROTTLE_BOUNDS.max_concurrency;
    }
    if (state.concurrency < THROTTLE_BOUNDS.min_concurrency) {
      state.concurrency = THROTTLE_BOUNDS.min_concurrency;
    }
    console.log(`      Loaded throttle state: concurrency=${state.concurrency}`);
    return state;
  }
  console.log(`      Using default throttle: concurrency=${DEFAULT_THROTTLE.concurrency}`);
  return { ...DEFAULT_THROTTLE };
}

// Save throttle state to S3
export async function saveThrottleState(state: ThrottleState): Promise<void> {
  if (await putObject(THROTTLE_STATE_KEY, state)) {
    console.log(`      Saved throttle state: concurrency=${state.concurrency}`);
  }
}

// Adjust throttle after a 429 error - reduce concurrency
export function throttleBackoff(state: ThrottleState): ThrottleState {
  const now = new Date().toISOString();
  const newState = { ...state };

  newState.last_429_at = now;
  newState.consecutive_429s += 1;
  newState.consecutive_successes = 0;

  // Reduce concurrency (rate limiting is handled separately by sliding window)
  if (newState.concurrency > THROTTLE_BOUNDS.min_concurrency) {
    newState.concurrency = Math.max(
      THROTTLE_BOUNDS.min_concurrency,
      newState.concurrency - THROTTLE_BOUNDS.concurrency_step
    );
    console.log(`      Throttle backoff: concurrency reduced to ${newState.concurrency}`);
  } else {
    console.log(`      Throttle backoff: already at min concurrency=${newState.concurrency}`);
  }

  return newState;
}

// Adjust throttle after a successful run (no 429s) - increase concurrency
export function throttleSpeedup(state: ThrottleState): ThrottleState {
  const now = new Date().toISOString();
  const newState = { ...state };

  newState.last_success_at = now;
  newState.consecutive_successes += 1;
  newState.consecutive_429s = 0;

  // Only consider speeding up after N consecutive successes
  if (newState.consecutive_successes < THROTTLE_BOUNDS.speedup_threshold) {
    return newState;
  }

  // Check if we can actually speed up
  if (newState.concurrency >= THROTTLE_BOUNDS.max_concurrency) {
    // Already at max concurrency, just keep counting successes
    return newState;
  }

  // Reset counter since we're actually making a change
  newState.consecutive_successes = 0;

  // Increase concurrency
  newState.concurrency = Math.min(
    THROTTLE_BOUNDS.max_concurrency,
    newState.concurrency + THROTTLE_BOUNDS.concurrency_step
  );

  console.log(`      Throttle speedup: concurrency increased to ${newState.concurrency}`);
  return newState;
}
