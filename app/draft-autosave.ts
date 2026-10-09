export interface DraftAutosaveOptions {
  save: () => Promise<void>;
  onPending: (pending: boolean) => void;
  onSaving: (saving: boolean) => void;
  onError: (error: unknown) => void;
  delayMs?: number;
}

// Serializes draft writes; edits made during a write require another save.
export class DraftAutosave {
  private version = 0;
  private savedVersion = 0;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private inFlight: Promise<void> | undefined;

  private readonly options: DraftAutosaveOptions;

  constructor(options: DraftAutosaveOptions) {
    this.options = options;
  }

  get pending(): boolean {
    return this.version !== this.savedVersion;
  }

  update(): void {
    this.version++;
    this.options.onPending(true);
    this.clearTimer();
    this.timer = setTimeout(() => {
      void this.flush().catch(() => undefined);
    }, this.options.delayMs ?? 700);
  }

  flush(): Promise<void> {
    this.clearTimer();
    if (this.inFlight) return this.inFlight;
    if (!this.pending) return Promise.resolve();
    this.inFlight = Promise.resolve().then(async () => {
      this.options.onSaving(true);
      try {
        while (this.pending) {
          const version = this.version;
          await this.options.save();
          this.savedVersion = version;
          this.options.onPending(this.pending);
        }
      } catch (error) {
        this.options.onError(error);
        throw error;
      } finally {
        this.clearTimer();
        this.inFlight = undefined;
        this.options.onSaving(false);
      }
    });
    return this.inFlight;
  }

  discard(): void {
    if (this.inFlight) throw new Error("Draft save is in progress");
    this.clearTimer();
    this.savedVersion = this.version;
    this.options.onPending(false);
  }

  dispose(): void {
    this.clearTimer();
  }

  private clearTimer(): void {
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
  }
}
