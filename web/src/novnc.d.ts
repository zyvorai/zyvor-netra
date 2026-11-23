declare module '@novnc/novnc' {
  export default class RFB {
    constructor(target: HTMLElement, url: string, options?: object);
    disconnect(): void;
    scaleViewport: boolean;
    resizeSession: boolean;
  }
}
