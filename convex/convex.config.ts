import { defineApp } from "convex/server";
import { v } from "convex/values";

export default defineApp({
  env: {
    WORKOS_CLIENT_ID: v.optional(v.string()),
    NEBULA_BOOTSTRAP_ADMIN_EMAIL: v.optional(v.string()),
  },
});
