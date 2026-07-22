/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as access from "../access.js";
import type * as attachments from "../attachments.js";
import type * as audit from "../audit.js";
import type * as authSettings from "../authSettings.js";
import type * as bootstrap from "../bootstrap.js";
import type * as devtools from "../devtools.js";
import type * as lib_access from "../lib/access.js";
import type * as lib_projects from "../lib/projects.js";
import type * as migrations from "../migrations.js";
import type * as projects from "../projects.js";
import type * as secrets from "../secrets.js";
import type * as users from "../users.js";
import type * as validators from "../validators.js";
import type * as workos from "../workos.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";

declare const fullApi: ApiFromModules<{
  access: typeof access;
  attachments: typeof attachments;
  audit: typeof audit;
  authSettings: typeof authSettings;
  bootstrap: typeof bootstrap;
  devtools: typeof devtools;
  "lib/access": typeof lib_access;
  "lib/projects": typeof lib_projects;
  migrations: typeof migrations;
  projects: typeof projects;
  secrets: typeof secrets;
  users: typeof users;
  validators: typeof validators;
  workos: typeof workos;
}>;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export declare const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, "public">
>;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export declare const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, "internal">
>;

export declare const components: {};
