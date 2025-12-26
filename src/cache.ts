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
// Validates loaded state against current bounds and resets if needed
export async function loadThrottleState(): Promise<ThrottleState> {
  const state = await getObject<ThrottleState>(THROTTLE_STATE_KEY);
  if (state) {
    // Validate concurrency is within bounds - reset if not
    if (state.concurrency > THROTTLE_BOUNDS.max_concurrency) {
      console.log(`      Cached throttle has invalid concurrency=${state.concurrency}, resetting to defaults`);
      return { ...DEFAULT_THROTTLE };
    }
    // Validate delay is within bounds
    if (state.delay_ms < THROTTLE_BOUNDS.min_delay_ms) {
      console.log(`      Cached throttle has invalid delay=${state.delay_ms}ms, resetting to defaults`);
      return { ...DEFAULT_THROTTLE };
    }
    console.log(`      Loaded throttle state: concurrency=${state.concurrency}, delay=${state.delay_ms}ms`);
    return state;
  }
  console.log(`      Using default throttle: concurrency=${DEFAULT_THROTTLE.concurrency}, delay=${DEFAULT_THROTTLE.delay_ms}ms`);
  return { ...DEFAULT_THROTTLE };
}

// Save throttle state to S3
export async function saveThrottleState(state: ThrottleState): Promise<void> {
  if (await putObject(THROTTLE_STATE_KEY, state)) {
    console.log(`      Saved throttle state: concurrency=${state.concurrency}, delay=${state.delay_ms}ms`);
  }
}

// Adjust throttle after a 429 error
export function throttleBackoff(state: ThrottleState): ThrottleState {
  const now = new Date().toISOString();
  const newState = { ...state };

  newState.last_429_at = now;
  newState.consecutive_429s += 1;
  newState.consecutive_successes = 0;

  // Reduce concurrency
  if (newState.concurrency > THROTTLE_BOUNDS.min_concurrency) {
    newState.concurrency = Math.max(
      THROTTLE_BOUNDS.min_concurrency,
      newState.concurrency - THROTTLE_BOUNDS.concurrency_step
    );
  }

  // Increase delay
  if (newState.delay_ms < THROTTLE_BOUNDS.max_delay_ms) {
    newState.delay_ms = Math.min(
      THROTTLE_BOUNDS.max_delay_ms,
      newState.delay_ms + THROTTLE_BOUNDS.delay_step_ms * newState.consecutive_429s
    );
  }

  console.log(`      Throttle backoff: concurrency=${newState.concurrency}, delay=${newState.delay_ms}ms`);
  return newState;
}

// Adjust throttle after a successful run (no 429s)
export function throttleSpeedup(state: ThrottleState): ThrottleState {
  const now = new Date().toISOString();
  const newState = { ...state };

  newState.last_success_at = now;
  newState.consecutive_successes += 1;
  newState.consecutive_429s = 0;

  // Only speed up after N consecutive successes
  if (newState.consecutive_successes < THROTTLE_BOUNDS.speedup_threshold) {
    return newState;
  }

  // Reset counter so we don't speed up every run
  newState.consecutive_successes = 0;

  // Increase concurrency
  if (newState.concurrency < THROTTLE_BOUNDS.max_concurrency) {
    newState.concurrency = Math.min(
      THROTTLE_BOUNDS.max_concurrency,
      newState.concurrency + THROTTLE_BOUNDS.concurrency_step
    );
  }

  // Decrease delay
  if (newState.delay_ms > THROTTLE_BOUNDS.min_delay_ms) {
    newState.delay_ms = Math.max(
      THROTTLE_BOUNDS.min_delay_ms,
      newState.delay_ms - THROTTLE_BOUNDS.delay_step_ms
    );
  }

  console.log(`      Throttle speedup: concurrency=${newState.concurrency}, delay=${newState.delay_ms}ms`);
  return newState;
}
