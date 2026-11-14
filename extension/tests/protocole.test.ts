// Essais du protocole côté extension (Web Crypto), sur les vecteurs communs
// avec le paquet Rust (crates/protocol/tests/vecteurs.json).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  type KeyPairRaw,
  ProtocolError,
  Session,
  decodeResponse,
  encodeJson,
  fingerprint,
  fromBase64,
  generateKeyPair,
  parseEnvelope,
  toBase64,
} from "../src/protocol";

interface Vectors {
  client_static_secret: string;
  client_static_public: string;
  app_static_secret: string;
  app_static_public: string;
  client_ephemeral_secret: string;
  client_ephemeral_public: string;
  app_ephemeral_secret: string;
  app_ephemeral_public: string;
  fingerprint: string;
  messages: { direction: string; n: number; plaintext: string; ciphertext: string }[];
}

const vectors = JSON.parse(
  readFileSync(new URL("../../crates/protocol/tests/vecteurs.json", import.meta.url), "utf8"),
) as Vectors;

const base64url = (b64: string) => Buffer.from(b64, "base64").toString("base64url");

/** Clé privée fixe des vecteurs, importée non exportable. */
async function fixed(secret: string, publicKey: string): Promise<KeyPairRaw> {
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    { kty: "OKP", crv: "X25519", d: base64url(secret), x: base64url(publicKey) },
    { name: "X25519" },
    false,
    ["deriveBits"],
  );
  return { privateKey, publicRaw: fromBase64(publicKey) };
}

async function vectorSessions(): Promise<{ extension: Session; app: Session }> {
  const clientStatic = await fixed(vectors.client_static_secret, vectors.client_static_public);
  const clientEph = await fixed(vectors.client_ephemeral_secret, vectors.client_ephemeral_public);
  const appStatic = await fixed(vectors.app_static_secret, vectors.app_static_public);
  const appEph = await fixed(vectors.app_ephemeral_secret, vectors.app_ephemeral_public);
  return {
    extension: await Session.establish(
      "extension",
      clientStatic,
      clientEph,
      appStatic.publicRaw,
      appEph.publicRaw,
    ),
    app: await Session.establish("application", appStatic, appEph, clientStatic.publicRaw, clientEph.publicRaw),
  };
}

test("même empreinte que l'application (vecteurs communs)", async () => {
  assert.equal(
    await fingerprint(fromBase64(vectors.app_static_public), fromBase64(vectors.client_static_public)),
    vectors.fingerprint,
  );
});

test("mêmes chiffrés que l'application, dans les deux sens (vecteurs communs)", async () => {
  const { extension, app } = await vectorSessions();
  const encoder = new TextEncoder();
  for (const message of vectors.messages) {
    const sender = message.direction === "extension-vers-app" ? extension : app;
    const { n, c } = await sender.seal(encoder.encode(message.plaintext));
    assert.equal(n, message.n);
    assert.equal(toBase64(c), message.ciphertext, `${message.direction} n° ${message.n}`);
  }
});

test("l'extension lit ce que l'application a chiffré (vecteurs communs)", async () => {
  const { extension } = await vectorSessions();
  const decoder = new TextDecoder();
  for (const message of vectors.messages.filter((m) => m.direction === "app-vers-extension")) {
    const plaintext = await extension.open(message.n, fromBase64(message.ciphertext));
    assert.equal(decoder.decode(plaintext), message.plaintext);
  }
});

test("rejeu, désordre, altération et autre session sont refusés", async () => {
  const clientStatic = await generateKeyPair();
  const clientEph = await generateKeyPair();
  const appStatic = await generateKeyPair();
  const appEph = await generateKeyPair();
  const extension = await Session.establish(
    "extension",
    clientStatic,
    clientEph,
    appStatic.publicRaw,
    appEph.publicRaw,
  );
  const app = await Session.establish("application", appStatic, appEph, clientStatic.publicRaw, clientEph.publicRaw);
  const first = await extension.seal(encodeJson({ op: "status", id: 1 }));
  const second = await extension.seal(encodeJson({ op: "status", id: 2 }));
  await assert.rejects(app.open(second.n, second.c), (e: ProtocolError) => e.code === "rejeu");
  const altered = Uint8Array.from(first.c);
  altered[0] = (altered[0] ?? 0) ^ 1;
  await assert.rejects(app.open(first.n, altered), (e: ProtocolError) => e.code === "message_altere");
  await app.open(first.n, first.c);
  await assert.rejects(app.open(first.n, first.c), (e: ProtocolError) => e.code === "rejeu");
  await app.open(second.n, second.c);
  // Renvoyé à son auteur : l'autre sens a une autre clé.
  const reply = await app.seal(encodeJson({ op: "ok", id: 2 }));
  await assert.rejects(app.open(reply.n, reply.c));
  const response = decodeResponse(await extension.open(reply.n, reply.c));
  assert.deepEqual(response, { op: "ok", id: 2 });
});

test("une clé publique d'ordre faible est refusée", async () => {
  const own = await generateKeyPair();
  const zero = new Uint8Array(32);
  await assert.rejects(
    Session.establish("extension", own, own, zero, zero),
    (e: ProtocolError) => e.code === "cle_refusee",
  );
});

test("les enveloppes inattendues sont refusées", () => {
  assert.deepEqual(parseEnvelope({ type: "msg", v: 1, n: 0, c: "AA==" }), { type: "msg", v: 1, n: 0, c: "AA==" });
  for (const bad of [
    null,
    "texte",
    { type: "msg", v: 2, n: 0, c: "AA==" },
    { type: "msg", v: 1, n: -1, c: "AA==" },
    { type: "msg", v: 1, n: 1.5, c: "AA==" },
    { type: "hello", v: 1, client: "a", eph: "b" },
    { type: "pair-result", v: 1, pairing: "p", state: "peut-etre" },
  ]) {
    assert.throws(() => parseEnvelope(bad), ProtocolError, JSON.stringify(bad));
  }
});
