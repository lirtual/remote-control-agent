/** Optional one-shot fault injector for the disposable rc-v2-receipt-lab Agent only.
 *  Never loaded by the ordinary v2 Agent. Only an explicitly named test
 *  write_file append to the disposable fixture can lose its completed reply.
 */
const FIXTURE = /^\/home\/rcagent\/receipt-v2-preview-test-[a-f0-9-]{36}\.txt$/;
const SENTINEL = "RC_V2_LOST_REPLY_ONCE\n";

export function dropOneCompletedWriteReply(socket, operationId, sharedState, onDrop = () => {}) {
  let matchingRequestId = null;
  socket.addEventListener("message", event => {
    if (sharedState.used || typeof event.data !== "string" || event.data.length > 65536) return;
    let frame;
    try { frame = JSON.parse(event.data); } catch { return; }
    if (frame?.kind !== "operation" || frame.tool !== "write_file" ||
        frame.operation_id !== operationId ||
        typeof frame.request_id !== "string" ||
        !/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(frame.request_id) ||
        frame.arguments?.mode !== "append" ||
        !FIXTURE.test(frame.arguments?.path) ||
        frame.arguments?.content !== SENTINEL) return;
    matchingRequestId = frame.request_id;
  });
  const send = socket.send.bind(socket);
  socket.send = data => {
    if (!sharedState.used && matchingRequestId && typeof data === "string" && data.length <= 65536) {
      let reply;
      try { reply = JSON.parse(data); } catch { /* ordinary heartbeat or reply */ }
      if (reply?.kind === "operation_result" &&
          reply.request_id === matchingRequestId &&
          reply.result?.operation_id === operationId &&
          reply.result?.status === "completed") {
        sharedState.used = true;
        onDrop();
        // Agent has already committed its SQLite Receipt; DO never gets this
        // reply. The usual reconnect logic will fetch a fresh signed nonce.
        socket.close(1011, "test lost reply");
        return;
      }
    }
    return send(data);
  };
  return socket;
}
