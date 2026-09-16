import '@testing-library/jest-dom';
import { TextEncoder, TextDecoder } from 'util';

global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

global.Request = global.Request || class Request {
  constructor(public input: RequestInfo | URL, public init?: RequestInit) {}
  public method = 'GET';
  public url = '';
  public headers = new Headers();
  public body = null;
  public bodyUsed = false;
  public clone() { return new Request(this.input, this.init); }
  public async text() { return ''; }
  public async json() { return {}; }
  public async blob() { return new Blob(); }
  public async arrayBuffer() { return new ArrayBuffer(0); }
  public async formData() { return new FormData(); }
} as unknown as typeof Request;

global.Response = global.Response || class Response {
  constructor(public body?: BodyInit | null, public init?: ResponseInit) {}
  public status = 200;
  public statusText = 'OK';
  public headers = new Headers();
  public ok = true;
  public url = '';
  public type = 'default';
  public bodyUsed = false;
  public clone() { return new Response(this.body, this.init); }
  public async text() { return ''; }
  public async json() { return {}; }
  public async blob() { return new Blob(); }
  public async arrayBuffer() { return new ArrayBuffer(0); }
  public async formData() { return new FormData(); }
  static error() { return new Response(null, { status: 0, statusText: '' }); }
  static redirect(url: string, status: number) { return new Response(null, { status, headers: { Location: url } }); }
} as unknown as typeof Response;

global.Headers = global.Headers || class Headers {
  private map = new Map<string, string>();
  constructor(init?: HeadersInit) {
    if (init) {
      if (Array.isArray(init)) {
        init.forEach(([k, v]) => this.map.set(k.toLowerCase(), v));
      } else if (typeof init === 'object') {
        Object.entries(init).forEach(([k, v]) => this.map.set(k.toLowerCase(), v));
      }
    }
  }
  append(name: string, value: string) { this.map.set(name.toLowerCase(), value); }
  delete(name: string) { this.map.delete(name.toLowerCase()); }
  get(name: string) { return this.map.get(name.toLowerCase()) || null; }
  has(name: string) { return this.map.has(name.toLowerCase()); }
  set(name: string, value: string) { this.map.set(name.toLowerCase(), value); }
  forEach(callbackfn: (value: string, key: string, parent: Headers) => void) { this.map.forEach((v, k) => callbackfn(v, k, this)); }
  *keys() { yield* this.map.keys(); }
  *values() { yield* this.map.values(); }
  *entries() { yield* this.map.entries(); }
  [Symbol.iterator]() { return this.entries(); }
} as unknown as typeof Headers;

global.fetch = global.fetch || jest.fn().mockResolvedValue(new Response());

Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: jest.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: jest.fn(),
    removeListener: jest.fn(),
    addEventListener: jest.fn(),
    removeEventListener: jest.fn(),
    dispatchEvent: jest.fn(),
  })),
});

Object.defineProperty(window, 'localStorage', {
  writable: true,
  value: {
    getItem: jest.fn(),
    setItem: jest.fn(),
    removeItem: jest.fn(),
    clear: jest.fn(),
  },
});

HTMLCanvasElement.prototype.getContext = jest.fn();