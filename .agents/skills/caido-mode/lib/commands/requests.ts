/** HTTP History commands: search, recent, get, get-response, export-curl */

import { getClient } from "../client";
import { decodeRaw, formatHttpRaw, rawToCurl } from "../output";
import type { OutputOpts } from "../types";

/**
 * Expand `preset:"name-or-alias"` clauses into the preset's own HTTPQL before the query is
 * sent.
 *
 * Caido's server does NOT resolve a `preset:` clause coming through this client, and — this
 * is the dangerous part — it does not error either. It returns the UNFILTERED set. Measured:
 * `preset:"ssrf-paths"` returned the full 500-row limit where the identical inline regex
 * returned 3. A query that looks filtered and is not is worse than no query at all, because
 * you draw conclusions from the wrong sample.
 *
 * So we resolve presets locally and, when a name does not exist, THROW rather than let a
 * silently-unfiltered result set through.
 */
export async function expandPresets(filter: string): Promise<string> {
  const re = /preset:\s*(?:"([^"]*)"|'([^']*)')/g;
  if (!re.test(filter)) return filter;
  re.lastIndex = 0;

  const client = await getClient();
  const presets: any[] = await client.filter.list();

  const lookup = (needle: string) => {
    const n = needle.trim().toLowerCase();
    return (
      presets.find(p => (p.alias || "").toLowerCase() === n) ||
      presets.find(p => (p.name || "").toLowerCase() === n) ||
      presets.find(p => String(p.id) === needle.trim())
    );
  };

  const missing: string[] = [];
  const expanded = filter.replace(re, (_m, dq, sq) => {
    const needle = dq !== undefined ? dq : sq;
    const hit = lookup(needle);
    if (!hit || !hit.clause) {
      missing.push(needle);
      return "";
    }
    return `(${hit.clause})`;
  });

  if (missing.length) {
    const known = presets
      .map(p => `${p.alias ? p.alias + " / " : ""}${p.name}`)
      .join(", ");
    throw new Error(
      `unknown filter preset(s): ${missing.join(", ")}\n` +
      `Refusing to run the query, because Caido would silently return the UNFILTERED set ` +
      `rather than an error.\nKnown presets: ${known || "(none)"}`
    );
  }
  return expanded;
}

export async function cmdSearch(filter: string, limit: number, after?: string, idsOnly?: boolean) {
  const client = await getClient();
  const effective = await expandPresets(filter);
  let builder = client.request.list().filter(effective).first(limit);
  if (after) builder = builder.after(after);

  const connection = await builder;

  if (idsOnly) {
    const ids = connection.edges.map(e => e.node.request.id);
    console.log(JSON.stringify(ids));
    return;
  }

  const results = connection.edges.map(e => ({
    id: e.node.request.id,
    method: e.node.request.method,
    host: e.node.request.host,
    path: e.node.request.path,
    query: e.node.request.query || undefined,
    isTls: e.node.request.isTls,
    port: e.node.request.port,
    statusCode: e.node.response?.statusCode,
    roundtrip: e.node.response?.roundtripTime,
    responseLength: e.node.response?.length,
    createdAt: e.node.request.createdAt,
    cursor: e.cursor,
  }));

  console.log(JSON.stringify({
    results,
    pageInfo: connection.pageInfo,
    count: results.length,
    ...(effective !== filter ? { expandedFilter: effective } : {}),
  }, null, 2));
}

export async function cmdRecent(limit: number) {
  const client = await getClient();
  const connection = await client.request.list()
    .descending("req", "id")
    .first(limit);

  const results = connection.edges.map(e => ({
    id: e.node.request.id,
    method: e.node.request.method,
    host: e.node.request.host,
    path: e.node.request.path,
    statusCode: e.node.response?.statusCode,
    roundtrip: e.node.response?.roundtripTime,
    createdAt: e.node.request.createdAt,
  }));

  console.log(JSON.stringify({ results, count: results.length }, null, 2));
}

export async function cmdGet(requestId: string, opts: OutputOpts) {
  const client = await getClient();
  const result = await client.request.get(requestId, { raw: true });

  if (!result) {
    console.error(`Request ${requestId} not found`);
    process.exit(1);
  }

  const output: Record<string, any> = {
    id: result.request.id,
    method: result.request.method,
    host: result.request.host,
    path: result.request.path,
    port: result.request.port,
    isTls: result.request.isTls,
    createdAt: result.request.createdAt,
  };

  if (!opts.noRequest && result.request.raw) {
    output.raw = formatHttpRaw(decodeRaw(result.request.raw), opts);
  }

  if (result.response) {
    output.response = {
      statusCode: result.response.statusCode,
      roundtrip: result.response.roundtripTime,
      length: result.response.length,
    };
    if (result.response.raw) {
      output.response.raw = formatHttpRaw(decodeRaw(result.response.raw), opts);
    }
  }

  console.log(JSON.stringify(output, null, 2));
}

export async function cmdGetResponse(requestId: string, opts: OutputOpts) {
  const client = await getClient();
  const result = await client.request.get(requestId, {
    requestRaw: false,
    responseRaw: true,
  });

  if (!result) {
    console.error(`Request ${requestId} not found`);
    process.exit(1);
  }

  if (!result.response) {
    console.log(JSON.stringify({ error: "No response for this request" }));
    return;
  }

  const output: Record<string, any> = {
    statusCode: result.response.statusCode,
    roundtrip: result.response.roundtripTime,
    length: result.response.length,
  };

  if (result.response.raw) {
    output.raw = formatHttpRaw(decodeRaw(result.response.raw), opts);
  }

  console.log(JSON.stringify(output, null, 2));
}

export async function cmdExportCurl(requestId: string) {
  const client = await getClient();
  const result = await client.request.get(requestId, { raw: true });

  if (!result) {
    console.error(`Request ${requestId} not found`);
    process.exit(1);
  }

  const raw = decodeRaw(result.request.raw);
  if (!raw) {
    console.error("No raw data for this request");
    process.exit(1);
  }

  const curl = rawToCurl(raw, result.request.host, result.request.port, result.request.isTls);
  console.log(curl);
}
