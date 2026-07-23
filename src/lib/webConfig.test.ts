import { describe, expect, test } from "vitest";
import { formatWebConfigEntries } from "./webConfig";

describe("formatWebConfigEntries", () => {
  test("formats one or more entries as web.config appSettings elements", () => {
    expect(
      formatWebConfigEntries([
        {
          key: "CognitionCustomerPortal.Authenticate.WASOverride",
          value: "False",
        },
        { key: "ApiBaseUrl", value: "https://example.test" },
      ]),
    ).toBe(
      [
        '<add key="CognitionCustomerPortal.Authenticate.WASOverride" value="False" />',
        '<add key="ApiBaseUrl" value="https://example.test" />',
      ].join("\n"),
    );
  });

  test("escapes XML attribute characters and preserves empty values", () => {
    expect(
      formatWebConfigEntries([
        { key: 'Feature "A" & <B>', value: "Tom's > Jerry's" },
        { key: "OptionalSetting", value: "" },
      ]),
    ).toBe(
      [
        '<add key="Feature &quot;A&quot; &amp; &lt;B&gt;" value="Tom&apos;s &gt; Jerry&apos;s" />',
        '<add key="OptionalSetting" value="" />',
      ].join("\n"),
    );
  });
});
