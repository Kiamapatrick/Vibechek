import { worker } from '@/mocks/browser';

export default async function globalSetup() {
  // Start MSW worker for E2E tests
  if (!process.env.CI) {
    await worker.start({
      onUnhandledRequest: 'warn',
      serviceWorker: {
        url: '/mockServiceWorker.js',
      },
    });
  }
}