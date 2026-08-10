import { useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { NextSeo } from 'next-seo';
import { HTTPError } from 'ky';
import { SubmitHandler, useForm, useWatch } from 'react-hook-form';
import {
  Button,
  Divider,
  Notification,
  Paper,
  PasswordInput,
  Stack,
  TextInput,
} from '@mantine/core';
import { IconAt, IconLock } from '@tabler/icons-react';

import GoogleSignInButton from './components/GoogleSignInButton';
import { useBrandDisplayName } from './theme/ThemeProvider';
import api from './api';
import * as config from './config';
import LandingHeader from './LandingHeader';
import { CheckOrX, PasswordCheck } from './PasswordCheck';

type FormData = {
  email: string;
  password: string;
  confirmPassword: string;
};

const AUTH_ERROR_MESSAGES: Record<string, string> = {
  missing: 'Please provide a valid email and password',
  invalid: 'Email or password is invalid',
  authFail: 'Failed to login with email and password, please try again.',
  passwordAuthNotAllowed:
    'Password authentication is not allowed by your team admin.',
  teamAlreadyExists: 'Team already exists, please login instead.',
  googleEmailUnverified:
    'Your Google email address is not verified. Verify it with Google and try again.',
  googleDomainNotAllowed:
    'This Google account is not permitted to sign in. Contact your admin.',
  googleNoTeam: 'No team has been set up yet. Register with a password first.',
  googleAccountMismatch:
    'This email is already linked to a different Google account. Contact your admin.',
  googleAuthFailed: 'Google sign-in failed, please try again.',
};

const DEFAULT_AUTH_ERROR = 'Unknown error occurred, please try again later.';

export default function AuthPage({ action }: { action: 'register' | 'login' }) {
  const brandName = useBrandDisplayName();
  const { data: team, isLoading: teamIsLoading } = api.useTeam();
  const router = useRouter();

  const isLoggedIn = Boolean(!teamIsLoading && team);

  useEffect(() => {
    if (isLoggedIn) {
      router.push('/search');
    }
  }, [isLoggedIn, router]);

  const isRegister = action === 'register';
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
    setError,
    control,
  } = useForm<FormData>({
    reValidateMode: 'onSubmit',
  });

  const { err, msg } = router.query;

  const { data: installation } = api.useInstallation();
  const isGoogleAuthEnabled =
    installation?.authProviders?.includes('google') === true;
  const registerPassword = api.useRegisterPassword();

  const verificationSent = msg === 'verify';

  const title = `${brandName} - ${isRegister ? 'Sign up' : 'Login'}`;

  useEffect(() => {
    // If an OSS user accidentally lands on /register after already creating a team
    // redirect them to login instead
    if (config.IS_OSS && installation?.isTeamExisting === true && isRegister) {
      router.push('/login');
    }
  }, [installation, isRegister, router]);

  const currentPassword = useWatch({
    control,
    name: 'password',
    defaultValue: '',
  });
  const confirmPassword = useWatch({
    control,
    name: 'confirmPassword',
    defaultValue: '',
  });

  const confirmPass = () => {
    return currentPassword === confirmPassword;
  };

  const onSubmit: SubmitHandler<FormData> = data =>
    registerPassword.mutate(
      {
        email: data.email,
        password: data.password,
        confirmPassword: data.confirmPassword,
      },
      {
        onSuccess: () => router.push('/search'),
        onError: async error => {
          if (error instanceof HTTPError) {
            const jsonData = await error.response.json();

            if (Array.isArray(jsonData) && jsonData[0]?.errors?.issues) {
              return jsonData[0].errors.issues.forEach((issue: any) => {
                setError(issue.path[0], {
                  type: issue.code,
                  message: issue.message,
                });
              });
            }
          }
          setError('root', {
            type: 'manual',
            message: 'An unexpected error occurred, please try again later.',
          });
        },
      },
    );

  const form = isRegister
    ? {
        controller: { onSubmit: handleSubmit(onSubmit) },
        email: register('email', { required: true }),
        password: register('password', { required: true }),
        confirmPassword: register('confirmPassword', { required: true }),
      }
    : {
        controller: {
          action: `/api/login/password`,
          method: 'POST',
        },
        email: { name: 'email' },
        password: { name: 'password' },
      };

  return (
    <div className="AuthPage">
      <NextSeo title={title} />
      <LandingHeader activeKey={`/${action}`} fixed />
      <div className="d-flex justify-content-center align-items-center vh-100">
        <div style={{ width: '26rem' }}>
          <div className="text-center mb-2 fs-5 " style={{ marginTop: -30 }}>
            {config.IS_OSS && isRegister
              ? 'Setup '
              : isRegister
                ? 'Register for '
                : 'Login to '}
            <span className="text-brand fw-bold">{brandName}</span>
          </div>
          {action === 'login' && (
            <div className="text-center mb-2 ">Welcome back!</div>
          )}
          {isRegister && config.IS_OSS === true && (
            <div className="text-center mb-2 text-muted">
              Let{"'"}s create your user account.
            </div>
          )}
          <form className="text-start mt-4" {...form.controller}>
            <Stack gap="xl">
              <Paper p={34} shadow="md" radius="md">
                <Stack gap="lg">
                  <TextInput
                    label="Email"
                    size="md"
                    withAsterisk={false}
                    placeholder="you@company.com"
                    type="email"
                    leftSection={<IconAt size={18} />}
                    error={errors.email?.message}
                    required
                    {...form.email}
                  />
                  <PasswordInput
                    size="md"
                    label="Password"
                    withAsterisk={false}
                    leftSection={<IconLock size={16} />}
                    error={errors.password?.message}
                    required
                    placeholder="Password"
                    {...form.password}
                  />
                  {isRegister && (
                    <>
                      <PasswordInput
                        label={
                          <CheckOrX
                            handler={confirmPass}
                            password={currentPassword}
                          >
                            Confirm Password
                          </CheckOrX>
                        }
                        size="md"
                        required
                        withAsterisk={false}
                        leftSection={<IconLock size={16} />}
                        error={errors.confirmPassword?.message}
                        placeholder="Confirm Password"
                        {...form.confirmPassword}
                      />
                      <Notification withCloseButton={false}>
                        <PasswordCheck password={currentPassword} />
                      </Notification>
                    </>
                  )}
                  <Button
                    mt={4}
                    type="submit"
                    variant="primary"
                    size="md"
                    disabled={isSubmitting || verificationSent}
                    loading={isSubmitting}
                    data-test-id="submit"
                  >
                    {config.IS_OSS && isRegister
                      ? 'Create'
                      : isRegister
                        ? 'Register'
                        : 'Login'}
                  </Button>
                  {isGoogleAuthEnabled && (
                    <>
                      <Divider label="or" labelPosition="center" />
                      <GoogleSignInButton />
                    </>
                  )}
                </Stack>
              </Paper>

              {err != null && (
                <Notification
                  withCloseButton={false}
                  withBorder
                  color="red"
                  data-test-id="auth-error-msg"
                >
                  {AUTH_ERROR_MESSAGES[String(err)] ?? DEFAULT_AUTH_ERROR}
                </Notification>
              )}

              {verificationSent && (
                <Notification
                  withCloseButton={false}
                  withBorder
                  color="green"
                  data-test-id="auth-msg"
                >
                  Sent verification email! Please check your email inbox
                </Notification>
              )}

              {isRegister && config.IS_OSS === false && (
                <div data-test-id="login-link" className="text-center fs-8 ">
                  Already have an account? <Link href="/login">Log in</Link>{' '}
                  instead.
                </div>
              )}
              {action === 'login' && config.IS_OSS === false && (
                <div data-test-id="register-link" className="text-center fs-8 ">
                  Don{"'"}t have an account yet?{' '}
                  <Link href="/register">Register</Link> instead.
                </div>
              )}
            </Stack>
          </form>
        </div>
      </div>
    </div>
  );
}
