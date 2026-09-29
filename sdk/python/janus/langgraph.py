"""Make LangGraph nodes Janus steps.

LangGraph owns the control flow, and this adapter does not take it over: the
graph decides which node runs when, and a Janus adapter with an opinion about
that would be a second scheduler disagreeing with the first. What Janus needs is
narrower — that when a node runs, the step is prepared with the facts it is
about to act on and reported when it is done.

So the adapter is an interceptor around `add_node`, and nothing more.
An application builds its graph exactly as it would without
Janus; the nodes are wrapped as they are added, by name.

Import this only if you use LangGraph; the SDK does not depend on it.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from janus._client import Client

# Facts picks what a node is about to act on out of the graph state. They are
# declared before the node body runs, so what a gate decides on is what the node
# was about to do rather than what it reports afterwards.
Facts = Callable[[dict[str, Any]], dict[str, Any]]


class GovernedGraph:
    """A StateGraph whose nodes are steps of a saga.

    Everything but `add_node` passes straight through, because everything but
    `add_node` is the graph's business. A node whose name is not a step of the
    saga is added unwrapped rather than refused: a graph may legitimately have
    nodes that do nothing to the world, and demanding a step declaration for
    each of them would push applications towards declaring steps that are not
    steps.
    """

    def __init__(
        self,
        graph: Any,
        client: Client,
        saga_id: str,
        facts: dict[str, Facts] | None = None,
    ) -> None:
        self._graph = graph
        self._client = client
        self._saga_id = saga_id
        self._facts = facts or {}

    def add_node(self, name: str, node: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        return self._graph.add_node(name, self._wrap(name, node), *args, **kwargs)

    def _wrap(self, step_id: str, node: Callable[..., Any]) -> Callable[..., Any]:
        pick = self._facts.get(step_id)

        @functools.wraps(node)
        def wrapper(state: dict[str, Any], *args: Any, **kwargs: Any) -> Any:
            declared = pick(state) if pick else {}
            with self._client.step(self._saga_id, step_id, **declared):
                return node(state, *args, **kwargs)

        return wrapper

    def __getattr__(self, name: str) -> Any:
        return getattr(self._graph, name)


def govern(
    graph: Any, client: Client, saga_id: str, facts: dict[str, Facts] | None = None
) -> GovernedGraph:
    """Wrap a StateGraph so its nodes are steps of a saga."""
    return GovernedGraph(graph, client, saga_id, facts)
