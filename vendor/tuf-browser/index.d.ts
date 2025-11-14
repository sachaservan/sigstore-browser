// Type definitions for vendored tuf-browser
// TODO: Replace with actual types from tuf-browser npm package when available

export class TUFClient {
  constructor(
    repositoryUrl: string,
    startingRoot: string,
    namespace: string,
    targetBaseUrl?: string
  );

  getTarget(name: string): Promise<Uint8Array>;
  listSignedTargets(): Promise<any>;
}
