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
//
// The delimiter search already reads the NAL type byte of every start code it
// crosses, so the same pass also describes each unit (keyframe? parameter
// sets?). Counting those downstream would mean a second scan of every byte of
// video for information this one already had in hand.

const START_CODE = Buffer.from([0, 0, 1]);
const NAL_IDR = 5;
const NAL_SEI = 6;
const NAL_SPS = 7;
const NAL_PPS = 8;
const NAL_AUD = 9;

// Well above one frame interval at the encoder's frame rates, so a stream in
// motion is framed by the next AUD and pays nothing; this is the ceiling on
// how long the LAST unit of a burst waits.
export const AU_FLUSH_MS = 50;

// ~16s of video at the encoder's 4 Mbit/s cap: no real access unit comes near
// it, so reaching it means the stream carries no delimiters and the buffer
// would otherwise grow without bound.
export const AU_MAX_PENDING = 8 * 1024 * 1024;

/** What one access unit carries, from the types the delimiter scan crossed. */
function describe(nals) {
  let idr = false;
  let sps = false;
  let pps = false;
  let sei = false;
  for (const type of nals) {
    if (type === NAL_IDR) idr = true;
    else if (type === NAL_SEI) sei = true;
    else if (type === NAL_SPS) sps = true;
    else if (type === NAL_PPS) pps = true;
  }
  return { idr, sps, pps, sei, nals };
}

/**
 * Frame an Annex-B byte stream into access units. `push(chunk)` takes stdout
 * chunks; `onAccessUnit(buf, info)` receives each complete unit, start code
 * first, with `info` = {idr, sps, pps, sei, nals} describing it (`nals` are
 * nal_unit_type values in stream order — empty for a payload that carried no
 * start code at all). `onResync()` fires when the buffer is dropped for
 * carrying no delimiter. `close()` stops the timer and drops any partial unit
 * — a replaced or dead encoder's tail belongs to no stream the next one will
 * produce.
 */
export function createAccessUnitFramer({
  onAccessUnit,
  onResync = () => {},
  flushMs = AU_FLUSH_MS,
  maxPending = AU_MAX_PENDING,
  log = () => {},
}) {
  let buf = Buffer.alloc(0);
  let searchFrom = 0;
  let timer = null;
  // NAL types crossed by the scan and where in `buf` each one sits, so an emit
  // can hand over exactly the ones inside the unit it cuts. `classifiedTo`
  // guards the re-scan that follows an emit: it walks back over the delimiter
  // that caused the cut, which must not be recorded twice.
  let types = [];
  let offsets = [];
  let classifiedTo = 0;

  function reset() {
    buf = Buffer.alloc(0);
    searchFrom = 0;
    types = [];
    offsets = [];
    classifiedTo = 0;
  }

  function emit(end) {
    const au = buf.subarray(0, end);
    buf = buf.subarray(end);
    let n = 0;
    while (n < offsets.length && offsets[n] < end) n++;
    const mine = types.splice(0, n);
    offsets.splice(0, n);
    for (let k = 0; k < offsets.length; k++) offsets[k] -= end;
    classifiedTo = Math.max(0, classifiedTo - end);
    onAccessUnit(au, describe(mine));
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
        const type = buf[at + 3] & 0x1f;
        if (at >= classifiedTo) {
          types.push(type);
          offsets.push(at);
          classifiedTo = at + 1;
        }
        if (type === NAL_AUD) {
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
        onResync();
        reset();
      }
      if (buf.length) armTimer();
      else stopTimer();
    },
    close() {
      stopTimer();
      reset();
    },
  };
}
