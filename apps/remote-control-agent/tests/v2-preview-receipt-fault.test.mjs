import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { dropOneCompletedWriteReply } from "../scripts/v2-preview-receipt-fault.mjs";

class FakeSocket extends EventTarget {
  sent = [];
  closed = [];
  send(data) { this.sent.push(data); }
  close(code, reason) { this.closed.push({ code, reason }); }
  receive(value) {
    const event = new Event("message");
    Object.defineProperty(event, "data", { value: JSON.stringify(value) });
    this.dispatchEvent(event);
  }
}
const path = "/home/rcagent/receipt-v2-preview-test-" + randomUUID() + ".txt";
const operationId = "receipt-fault-20261016-" + randomUUID().slice(0, 8);
const req = (request_id, overrides = {}) => ({
  kind: "operation", request_id, tool: "write_file",
  operation_id: operationId,
  arguments: { path, mode: "append", content: "RC_V2_LOST_REPLY_ONCE\n" },
  ...overrides,
});
const reply = (request_id, status = "completed") => ({
  kind: "operation_result", request_id,
  result: { operation_id: operationId, status },
});

test("only the first completed matching fixture write drops its outbound WSS reply", () => {
  const state = { used: false }, socket = new FakeSocket();
  let drops = 0;
  dropOneCompletedWriteReply(socket, operationId, state, () => { drops++; });
  const request_id = randomUUID();
  socket.send("rc-v2:ping");
  socket.receive(req(request_id));
  socket.send(JSON.stringify(reply(request_id)));
  assert.equal(state.used, true);
  assert.equal(drops, 1);
  assert.deepEqual(socket.sent, ["rc-v2:ping"]);
  assert.deepEqual(socket.closed, [{ code: 1011, reason: "test lost reply" }]);

  // A freshly signed WSS incarnation shares the same one-shot guard.
  const nextSocket = new FakeSocket();
  dropOneCompletedWriteReply(nextSocket, operationId, state, () => { drops++; });
  nextSocket.receive(req(randomUUID()));
  nextSocket.send(JSON.stringify(reply(request_id)));
  assert.equal(nextSocket.sent.length, 1);
  assert.equal(nextSocket.closed.length, 0);
  assert.equal(drops, 1);
});

test("unrelated writes, Shell, wrong paths and failed receipts are never swallowed", () => {
  const state = { used: false }, socket = new FakeSocket();
  dropOneCompletedWriteReply(socket, operationId, state);
  const other = randomUUID(), target = randomUUID();
  socket.receive(req(other, { operation_id: "other-operation" }));
  socket.send(JSON.stringify(reply(other)));
  socket.receive(req(randomUUID(), { tool: "start_process" }));
  socket.receive(req(randomUUID(), { arguments: { path: "/etc/passwd", mode: "append",
    content: "RC_V2_LOST_REPLY_ONCE\n" } }));
  socket.receive(req(target));
  socket.send(JSON.stringify(reply(target, "conflict")));
  assert.equal(state.used, false);
  assert.equal(socket.sent.length, 2);
  assert.equal(socket.closed.length, 0);
  socket.send(JSON.stringify(reply(target)));
  assert.equal(state.used, true);
  assert.equal(socket.sent.length, 2);
  assert.equal(socket.closed.length, 1);
});

test("an invalid or nonmatching request ID never triggers the injector", () => {
  const state = { used: false }, socket = new FakeSocket();
  dropOneCompletedWriteReply(socket, operationId, state);
  socket.receive(req("bad-request-id"));
  socket.send(JSON.stringify(reply("bad-request-id")));
  socket.receive(req(randomUUID(), { arguments: { path, mode: "rewrite",
    content: "RC_V2_LOST_REPLY_ONCE\n" } }));
  socket.send(JSON.stringify(reply(randomUUID())));
  assert.equal(state.used, false);
  assert.equal(socket.sent.length, 2);
  assert.equal(socket.closed.length, 0);
});
