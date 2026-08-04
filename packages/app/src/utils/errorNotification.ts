import type { HTTPError } from 'ky';
import { notifications } from '@mantine/notifications';

/**
 * Read the API's error message off a failed request.
 *
 * Every JSON error the API returns carries its text in `message` — including
 * RBAC denials, which respond `403 { message, required: { resource, level } }`.
 * Handlers that look for a different key (or ignore the error entirely) end up
 * showing a hardcoded fallback, which is worse than useless when the fallback
 * blames the wrong thing: "check the host and credentials" for what is really
 * a permissions problem sends the user to debug their ClickHouse config.
 *
 * Defensive on every hop: network failures reject with no `response` at all,
 * and a non-JSON body throws on `.json()`.
 */
export async function getApiErrorMessage(
  error: unknown,
  fallback: string,
): Promise<string> {
  try {
    const body: unknown = await (error as HTTPError)?.response?.json();
    if (
      body != null &&
      typeof body === 'object' &&
      'message' in body &&
      typeof (body as { message: unknown }).message === 'string' &&
      (body as { message: string }).message.length > 0
    ) {
      return (body as { message: string }).message;
    }
  } catch {
    // Body was not JSON — the fallback already says something useful.
  }
  return fallback;
}

/** Show the API's error message as a red notification, or `fallback`. */
export async function showApiErrorNotification(
  error: unknown,
  fallback: string,
): Promise<void> {
  notifications.show({
    color: 'red',
    message: await getApiErrorMessage(error, fallback),
    autoClose: 5000,
  });
}
