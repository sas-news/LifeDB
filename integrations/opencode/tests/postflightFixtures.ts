import type { AssistantMessage, Message, Part, TextPart, UserMessage } from "@opencode-ai/sdk";

export const SESSION = "ses-postflight";
export const DIRECTORY = "/srv/project";
export const WORKSPACE = "/srv/project";
export const TOKEN = "k".repeat(32);

export function user(id: string, text = "question"): { readonly info: UserMessage; readonly parts: Part[] } {
  return {
    info: { id, sessionID: SESSION, role: "user", time: { created: 1000 }, agent: "build", model: { providerID: "provider", modelID: "model" } },
    parts: [{ id: `${id}-text`, sessionID: SESSION, messageID: id, type: "text", text }],
  };
}

export function assistant(id: string, parentID: string, completed = 3000, text = "answer"): { readonly info: AssistantMessage; readonly parts: Part[] } {
  return {
    info: { id, sessionID: SESSION, role: "assistant", time: { created: 2000, completed }, parentID, modelID: "model", providerID: "provider", mode: "build", path: { cwd: DIRECTORY, root: DIRECTORY }, cost: 0, tokens: { input: 1, output: 1, reasoning: 1, cache: { read: 0, write: 0 } }, finish: "stop" },
    parts: [{ id: `${id}-text`, sessionID: SESSION, messageID: id, type: "text", text }],
  };
}

export function messageList(...items: Array<{ readonly info: Message; readonly parts: Part[] }>): Array<{ info: Message; parts: Part[] }> {
  return items.map((item) => ({ info: item.info, parts: [...item.parts] }));
}

export function idle(sessionID = SESSION): { readonly event: { readonly type: "session.idle"; readonly properties: { readonly sessionID: string } } } {
  return { event: { type: "session.idle", properties: { sessionID } } };
}

export function text(messageID: string, textValue: string, flags: { readonly synthetic?: boolean; readonly ignored?: boolean } = {}): TextPart {
  return { id: `${messageID}-${textValue}`, sessionID: SESSION, messageID, type: "text", text: textValue, ...flags };
}
