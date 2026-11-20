declare module '@novnc/novnc/lib/rfb.js' {
  export default class RFB {
    constructor(target: HTMLElement, url: string, options?: object);
    disconnect(): void;
    scaleViewport: boolean;
    resizeSession: boolean;
  }
}
