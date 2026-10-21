import { useCallback, useEffect, useRef, useState } from "react";

export type Playback = {
  step: number;
  total: number;
  playing: boolean;
  finished: boolean;
  toggle: () => void;
  restart: () => void;
  skip: () => void;
};

function prefersReducedMotion(): boolean {
  return window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
}

export function usePlayback(durations: number[], startFinished = false): Playback {
  const total = durations.length;
  const reduced = useRef(startFinished || prefersReducedMotion());
  const [step, setStep] = useState(reduced.current ? total : 0);
  const [playing, setPlaying] = useState(!reduced.current);
  const finished = step >= total;

  useEffect(() => {
    if (!playing || finished) return;
    const timer = window.setTimeout(() => setStep((current) => current + 1), durations[step]);
    return () => window.clearTimeout(timer);
  }, [playing, finished, step, durations]);

  useEffect(() => {
    if (finished) setPlaying(false);
  }, [finished]);

  const toggle = useCallback(() => setPlaying((current) => !current), []);
  const restart = useCallback(() => {
    setStep(0);
    setPlaying(true);
  }, []);
  const skip = useCallback(() => {
    setStep(total);
    setPlaying(false);
  }, [total]);

  return { step, total, playing, finished, toggle, restart, skip };
}

export function useCountUp(target: number, running: boolean, durationMs = 900): number {
  const [value, setValue] = useState(running ? 0 : target);

  useEffect(() => {
    if (!running || prefersReducedMotion()) {
      setValue(target);
      return;
    }
    let frame = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const progress = Math.min(1, (now - start) / durationMs);
      setValue(Math.round(target * progress));
      if (progress < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target, running, durationMs]);

  return value;
}
