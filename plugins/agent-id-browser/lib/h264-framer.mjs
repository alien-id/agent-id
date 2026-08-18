// Access-unit framing for the Annex-B byte stream an encoder writes to stdout.
//
// A pipe read is capped at 64 KiB below Node (not tunable — raising
// readableHighWaterMark changes nothing), so an access unit bigger than that
// arrives split across chunks, and the tail chunk carries NO start code at all
// (emulation prevention keeps 00 00 01 out of NAL bodies). A consumer that
// parses one access unit per message therefore sees the tail as nothing,
// resyncs, and waits for a keyframe — and since the IDR is the largest access
// unit in the stream, the very frame that would clear that wait is the one
// most likely to be split. The picture freezes or goes black.
//
// So the byte stream is buffered and cut on access unit delimiters (NAL type
// 9, which the encoder inserts for exactly this purpose), and each complete
// access unit is handed over whole, however large.
//
// An AUD marks the START of an access unit, so unit N is only known-complete
// when unit N+1's AUD arrives — on a page that stops producing frames that
// would hold the last unit indefinitely. An idle timer, reset by every chunk,
// flushes it instead. The timer only fires when the encoder produced nothing
// for the whole interval, and it is orders of magnitude longer than the gaps
// inside one unit's writes (the writer refills the 64 KiB pipe buffer as fast
// as this process drains it, and a timer cannot fire while the event loop is
// too busy to drain), so it does not split a unit it is meant to deliver.

const START_CODE = Buffer.from([0, 0, 1]);
const NAL_AUD = 9;

// Well above one frame interval at the encoder's frame rates, so a stream in
// motion is framed by the next AUD and pays nothing; this is the ceiling on
// how long the LAST unit of a burst waits.
export const AU_FLUSH_MS = 50;

// ~16s of video at the encoder's 4 Mbit/s cap: no real access unit comes near
// it, so reaching it means the stream carries no delimiters and the buffer
// would otherwise grow without bound.
export const AU_MAX_PENDING = 8 * 1024 * 1024;

/**
 * Frame an Annex-B byte stream into access units. `push(chunk)` takes stdout
 * chunks; `onAccessUnit(buf)` receives each complete unit, start code first.
 * `close()` stops the timer and drops any partial unit — a replaced or dead
 * encoder's tail belongs to no stream the next one will produce.
 */
export function createAccessUnitFramer({
  onAccessUnit,
  flushMs = AU_FLUSH_MS,
  maxPending = AU_MAX_PENDING,
  log = () => {},
}) {
  let buf = Buffer.alloc(0);
  let searchFrom = 0;
  let timer = null;

  function emit(end) {
    const au = buf.subarray(0, end);
    buf = buf.subarray(end);
    onAccessUnit(au);
  }

  function stopTimer() {
    if (timer) clearTimeout(timer);
    timer = null;
  }

  function armTimer() {
    stopTimer();
    timer = setTimeout(() => {
      timer = null;
      if (buf.length) emit(buf.length);
    }, flushMs);
    timer.unref?.();
  }

  return {
    push(chunk) {
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      let i = searchFrom;
      for (;;) {
        const at = buf.indexOf(START_CODE, i);
        // Undecidable until the NAL type byte arrives: rescan next chunk.
        if (at < 0 || at + 3 >= buf.length) break;
        if ((buf[at + 3] & 0x1f) === NAL_AUD) {
          // A 4-byte start code owns its leading zero, so cut before it —
          // every emitted unit begins with a start code.
          const cut = at > 0 && buf[at - 1] === 0 ? at - 1 : at;
          if (cut > 0) {
            emit(cut);
            i = 1; // past the delimiter now sitting at the head
            continue;
          }
        }
        i = at + 3;
      }
      searchFrom = Math.max(0, buf.length - 3);
      if (buf.length > maxPending) {
        log("stream: no access unit delimiter within the frame buffer — resyncing");
        buf = Buffer.alloc(0);
        searchFrom = 0;
      }
      if (buf.length) armTimer();
      else stopTimer();
    },
    close() {
      stopTimer();
      buf = Buffer.alloc(0);
      searchFrom = 0;
    },
  };
}
