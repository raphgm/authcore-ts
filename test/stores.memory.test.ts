import { MemoryRateLimiter, MemoryResetTokenStore, MemoryUserStore } from "../src/index.js";
import { describeStoreContract } from "./contract.js";
import { makeUser } from "./helpers.js";

describeStoreContract("memory", () => {
  const users = new MemoryUserStore();
  return Promise.resolve({
    users,
    tokens: new MemoryResetTokenStore(),
    limiter: new MemoryRateLimiter(),
    seed: (user) => {
      users.add(makeUser({ ...user, passwordHash: user.passwordHash ?? "hash", active: user.active ?? true }));
      return Promise.resolve();
    },
  });
});
