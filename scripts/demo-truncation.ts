// bcrypt only reads the first 72 bytes of a password.
import bcrypt from "bcryptjs";
import { PasswordHasher } from "../src/index.js";

const shared = "correct-horse-battery-staple-".repeat(3).slice(0, 72);
const first = `${shared}FIRST-password-tail`;
const second = `${shared}SECOND-different-tail`;

console.log(`two different passwords, ${Buffer.byteLength(first)} and ${Buffer.byteLength(second)} bytes, identical for the first 72 bytes\n`);

const plain = await bcrypt.hash(first, 10);
console.log(`plain bcrypt   : hash(first), then check(second) -> ${String(await bcrypt.compare(second, plain))}   <- accepted the wrong password`);

const hasher = new PasswordHasher({ cost: 10 });
const safe = await hasher.hash(first);
console.log(`authcore-ts    : hash(first), then check(second) -> ${String(await hasher.verify(second, safe))}  <- rejected`);
console.log(`authcore-ts    : hash(first), then check(first)  -> ${String(await hasher.verify(first, safe))}`);
console.log(`\nstored hash prefix: ${safe.slice(0, 26)}...`);
