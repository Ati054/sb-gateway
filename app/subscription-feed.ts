type FeedNode = {
  subscription_id?: unknown;
  subscription_display_name?: unknown;
};

export type SubscriptionFeed<T> = {
  id: string;
  name: string;
  nodes: T[];
};

// The API already returns subscriptions and their nodes in provider order.
// Grouping must never sort the feed or derive a group from a display label.
export function subscriptionFeedGroups<T extends FeedNode>(nodes: readonly T[]): SubscriptionFeed<T>[] {
  const feeds = new Map<string, SubscriptionFeed<T>>();
  for (const node of nodes) {
    const id = typeof node.subscription_id === "string" && node.subscription_id
      ? node.subscription_id
      : "unknown";
    const name = typeof node.subscription_display_name === "string" && node.subscription_display_name
      ? node.subscription_display_name
      : id;
    const feed = feeds.get(id);
    if (feed) feed.nodes.push(node);
    else feeds.set(id, { id, name, nodes: [node] });
  }
  return [...feeds.values()];
}
