import type { JsonObject } from "./api-client";

const flagCodes = new Set("ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bv bw by bz ca cc cd cf cg ch ci ck cl cm cn co cp cr cu cv cw cx cy cz de dg dj dk dm do dz ec ee eg eh er es et eu fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu ic id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pc pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sj sk sl sm sn so sr ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug um un us uy uz va vc ve vg vi vn vu wf ws xk ye yt za zm zw".split(" "));

export function nodePresentation(label: string, country = "") {
  const emoji = label.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u)?.[0];
  const code = (emoji
    ? [...emoji].map((part) => String.fromCharCode(part.codePointAt(0)! - 0x1f1e6 + 65)).join("")
    : country).toLowerCase();
  if (!flagCodes.has(code)) return { label, flag: "" };
  return { label: emoji ? label.replace(emoji, "").trim() : label, flag: `/flags/${code}.svg` };
}

// Selection and membership are runtime facts, independent of measured history.
export function selectorCandidateIds(health: JsonObject, stats: JsonObject): string[] {
  const labels = health.candidate_labels;
  const ids = labels && typeof labels === "object" && !Array.isArray(labels)
    ? Object.keys(labels) : Object.keys(stats);
  const selected = health.runtime_confirmed === true ? health.runtime_selected : "";
  return [...new Set([...ids, ...(typeof selected === "string" && selected && selected !== "block" ? [selected] : [])])];
}

export function nodeProtocolSuffix(node?: JsonObject): string {
  const protocol = typeof node?.protocol === "string" ? node.protocol.toLowerCase() : "";
  const transport = typeof node?.transport === "string" ? node.transport.toLowerCase() : "";
  if (["hysteria2", "hy2"].includes(protocol)) return "H2";
  if (["wireguard", "routeros-wireguard"].includes(protocol)) return "WG";
  if (protocol === "xray-reverse") return "REV";
  const names: Record<string, string> = {ws:"WS", grpc:"gRPC", xhttp:"XHTTP", splithttp:"XHTTP", httpupgrade:"HU", tcp:"TCP"};
  if (protocol === "reality") return transport && transport !== "tcp" ? `${names[transport] ?? transport}+R` : "R";
  return names[transport] ?? ({vless:"VLESS", trojan:"Trojan", vmess:"VMess", shadowsocks:"SS"}[protocol] ?? "");
}

function nodeSourceLabel(node?: JsonObject): string {
  return typeof node?.subscription_display_name === "string"
    ? node.subscription_display_name.trim()
    : "";
}

export function nodeDisplayLabel(label: string, node?: JsonObject, peers: JsonObject[] = []): string {
  if (!node) return label;
  const collisions = peers.filter(peer => peer.label === label);
  if (collisions.length < 2) return label;

  const suffix = nodeProtocolSuffix(node);
  let equivalent = collisions.filter(peer => nodeProtocolSuffix(peer) === suffix);
  const source = nodeSourceLabel(node);
  const qualifier = [suffix];

  // Protocol normally distinguishes equal provider labels. If two independent
  // subscriptions still expose the same protocol and name, use their public
  // display names rather than leaking internal subscription IDs.
  if (equivalent.length > 1 && source) {
    qualifier.push(source);
    equivalent = equivalent.filter(peer => nodeSourceLabel(peer) === source);
  }

  // A provider may publish genuinely indistinguishable duplicate entries.
  // Keep their stable identities separate with a deterministic occurrence.
  if (equivalent.length > 1 && typeof node.id === "string" && node.id) {
    const ids = equivalent
      .map(peer => typeof peer.id === "string" ? peer.id : "")
      .filter(Boolean)
      .sort();
    const index = ids.indexOf(node.id);
    if (index >= 0) qualifier.push(`#${index + 1}`);
  }

  const detail = qualifier.filter(Boolean).join(" · ");
  return detail ? `${label} (${detail})` : label;
}

function comparableLabel(value: string): string {
  return value
    .normalize("NFC")
    .toLocaleLowerCase("ru")
    .replace(/[^\p{L}\p{N}]+/gu, " ")
    .trim();
}

function labelContains(title: string, value: string): boolean {
  const titleKey = comparableLabel(title);
  const valueKey = comparableLabel(value);
  return valueKey.length > 1 && titleKey.includes(valueKey);
}

// Provider labels often already contain their country and city. Priority rows
// keep that identity as the title and show only facts that add information.
export function nodeLocationDetail(
  title: string,
  country: string,
  city: string,
  provider: string,
  protocol: string,
): string {
  const parts: string[] = [];
  if (!labelContains(title, city)) {
    if (country && !labelContains(title, country)) parts.push(country);
    if (city && !labelContains(title, city)) parts.push(city);
  }
  for (const value of [provider, protocol]) {
    if (
      value &&
      !labelContains(title, value) &&
      !parts.some((part) => comparableLabel(part) === comparableLabel(value))
    ) {
      parts.push(value);
    }
  }
  return parts.join(" · ");
}

// Never mix refreshed subscription IDs with the applied generation. Identical
// names are not identities: distinct protocols/providers must remain distinct.
export function routeCandidateIds(health: JsonObject, stats: JsonObject, chosen: string[]): string[] {
  if (health.candidate_labels && typeof health.candidate_labels === "object" && !Array.isArray(health.candidate_labels)) return selectorCandidateIds(health, stats);
  return [...new Set([...chosen, ...selectorCandidateIds(health, stats)])];
}

export function compareRouteCandidates(left: {selected:boolean; available:boolean; inRuntimePool:boolean; availabilityKnown:boolean}, right: typeof left): number {
  const rank = (node: typeof left) => node.selected ? 0 : node.available && node.inRuntimePool ? 1 : node.available ? 2 : !node.availabilityKnown ? 3 : 4;
  return rank(left) - rank(right);
}
