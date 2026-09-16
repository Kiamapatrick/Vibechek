import { worker } from '@/mocks/browser';

export default async function globalTeardown() {
  await worker.stop();
}