// Per-second frame counters for the viewport stream.
//
// The question a frozen picture asks is "which stage lost the frame", and one
// counter row per stage per second answers it without per-frame logging. That
// restraint is not only about cost: the capture stage discards a frame when a
// viewer stalls and the encode stage disconnects a viewer past a buffer bound,
// so logging either at frame rate is capable of manufacturing the freeze being
// investigated. Every event here is an integer add and one branch; the JSON is
// built once per second.
//
// The wire shape is fixed by a contract shared with the other stages that
// carry the same picture, so the field names are not ours to rename: `fi`/`fo`
// frames in/out, `bi`/`bo` bytes, `drop` with a per-reason breakdown in `dr`,
// `seq` for the envelope range, cumulative twins in `c`, and `zero` — which is
// redundant with the counters on purpose, so a freeze greps without
// arithmetic. A copy of the schema is vendored under tests/fixtures and every
// emitted line is validated against it.

const V = 1;

/**
 * One stage's counters. `in`/`out`/`lost` are the per-frame surface; `note`
 * records an envelope sequence number; `close` renders and resets the window.
 * `nal` adds the H.264 fields (idr/sps/pps/perr) to the rendered line.
 */
export function createHopCounters(hop, { nal = false } = {}) {
  const total = { fi: 0, fo: 0, bi: 0, bo: 0, drop: 0, idr: 0, perr: 0 };
  const c = {
    hop,
    fi: 0, fo: 0, bi: 0, bo: 0, drop: 0,
    idr: 0, sps: 0, pps: 0, perr: 0,
    dr: null,
    seq: null,
    prevSeq: null,
    since: Date.now(),
    // A stage that has counted nothing is in the same state as a frozen one,
    // and that is the state a leave_zero edge fires out of.
    lastZero: true,
    onLeaveZero: null,

    in(bytes) {
      c.fi++;
      c.bi += bytes;
      if (c.lastZero) c.wake();
    },
    out(bytes) {
      c.fo++;
      c.bo += bytes;
      if (c.lastZero) c.wake();
    },
    lost(reason) {
      c.drop++;
      c.dr ??= Object.create(null);
      c.dr[reason] = (c.dr[reason] ?? 0) + 1;
      if (c.lastZero) c.wake();
    },
    wake() {
      c.lastZero = false; // cleared first: the emit re-enters through close()
      c.onLeaveZero?.();
    },

    // Discontinuities are counted across the window boundary too, or every
    // tick would hide one. A number that went BACKWARDS is a restart replaying
    // from zero, not a 10^6-frame gap, and consumers need to be told which.
    note(seq) {
      const s = (c.seq ??= { first: seq, last: seq, gaps: 0 });
      if (seq < s.first) s.first = seq;
      if (seq > s.last) s.last = seq;
      if (c.prevSeq !== null) {
        if (seq < c.prevSeq) s.reset = true;
        else if (seq !== c.prevSeq + 1) s.gaps++;
      }
      c.prevSeq = seq;
    },

    zeroNow() {
      return c.fi === 0 && c.fo === 0 && c.drop === 0;
    },

    close(now, edge) {
      const zero = c.zeroNow();
      const line = {
        v: V,
        hop,
        t: Math.floor(c.since / 1000),
        win_ms: Math.max(1, now - c.since),
        fi: c.fi, fo: c.fo, bi: c.bi, bo: c.bo, drop: c.drop,
      };
      if (c.dr) line.dr = c.dr;
      if (nal) {
        line.idr = c.idr;
        line.sps = c.sps;
        line.pps = c.pps;
        line.perr = c.perr;
      }
      if (c.seq) line.seq = c.seq;
      line.zero = zero;
      if (edge) line.edge = edge;
      total.fi += c.fi;
      total.fo += c.fo;
      total.bi += c.bi;
      total.bo += c.bo;
      total.drop += c.drop;
      total.idr += c.idr;
      total.perr += c.perr;
      // Cumulative twins survive a lost line: two non-adjacent lines still
      // yield an exact total.
      line.c = { fi: total.fi, fo: total.fo, bi: total.bi, bo: total.bo, drop: total.drop };
      if (nal) {
        line.c.idr = total.idr;
        line.c.perr = total.perr;
      }
      c.fi = c.fo = c.bi = c.bo = c.drop = 0;
      c.idr = c.sps = c.pps = c.perr = 0;
      c.dr = null;
      c.seq = null;
      c.since = now;
      c.lastZero = zero;
      return line;
    },
  };
  return c;
}

/**
 * Drive `rows` on the wall-clock second, emitting one line each. `t` is the
 * window start in unix seconds and the primary join key across every stage
 * that carries the picture, so the tick aligns to the second boundary rather
 * than running a 1000 ms interval from whenever this happened to start, and
 * `win_ms` reports what actually elapsed so a late or coalesced tick shows up
 * instead of silently skewing every rate derived from it.
 */
export function startCounterTicker({ rows, emit, now = () => Date.now() }) {
  let timer = null;
  let stopped = false;

  function schedule() {
    if (stopped) return;
    timer = setTimeout(fire, Math.max(1, 1000 - (now() % 1000)));
    timer.unref?.();
  }

  function fire() {
    const at = now();
    for (const c of rows) {
      // A freeze ENDS at an event, so that boundary is knowable to the
      // millisecond and is emitted out of band by onLeaveZero. A freeze BEGINS
      // at the absence of events, which only the closing tick can observe.
      emit(c.close(at, c.zeroNow() && !c.lastZero ? "enter_zero" : undefined));
    }
    schedule();
  }

  for (const c of rows) {
    c.since = now();
    c.onLeaveZero = () => emit(c.close(now(), "leave_zero"));
  }
  schedule();

  return {
    stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      timer = null;
      for (const c of rows) c.onLeaveZero = null;
    },
  };
}
