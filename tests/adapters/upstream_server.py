"""A real MCP server, used as the upstream in the proxy tests.

Not a fixture object and not a mock: a separate process speaking the MCP wire
protocol over stdio through the official SDK, which is what SPEC §22's week 2
exit criterion means by "against a real MCP server". A fake would pass while the
proxy's transport handling was broken.

The tool list is chosen to cover the classification cases that matter: a mild
verb carrying a destructive payload (``execute_sql`` with ``DROP TABLE``), an
obviously destructive verb, a bulk selector, and a plain read.
"""

from __future__ import annotations

import anyio
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

NAME = "orders-db"
VERSION = "3.1.4"
INSTRUCTIONS = "The orders database. Be careful."

TOOLS = [
    types.Tool(
        name="execute_sql",
        description="Run one SQL statement.",
        inputSchema={
            "type": "object",
            "properties": {"sql": {"type": "string"}, "table": {"type": "string"}},
            "required": ["sql"],
        },
    ),
    types.Tool(
        name="delete_rows",
        description="Delete rows matching a selector.",
        inputSchema={
            "type": "object",
            "properties": {"table": {"type": "string"}, "selector": {"type": "string"}},
        },
    ),
    types.Tool(
        name="list_tables",
        description="List the tables.",
        inputSchema={"type": "object", "properties": {}},
    ),
    types.Tool(
        name="explode",
        description="Always fails, so the proxy's error path is exercised.",
        inputSchema={"type": "object", "properties": {}},
    ),
]

RESOURCES = [
    types.Resource(
        uri="db://orders/schema",  # type: ignore[arg-type]
        name="schema",
        description="The schema of the orders database.",
        mimeType="text/plain",
    )
]

PROMPTS = [types.Prompt(name="explain-schema", description="Explain the schema.")]


async def on_list_tools(
    ctx: object, params: types.PaginatedRequestParams | None
) -> types.ListToolsResult:
    return types.ListToolsResult(tools=TOOLS)


async def on_call_tool(ctx: object, params: types.CallToolRequestParams) -> types.CallToolResult:
    if params.name == "explode":
        raise ValueError("the upstream tool failed on purpose")
    return types.CallToolResult(
        content=[
            types.TextContent(type="text", text=f"{NAME}.{params.name} ran with {params.arguments}")
        ]
    )


async def on_list_resources(
    ctx: object, params: types.PaginatedRequestParams | None
) -> types.ListResourcesResult:
    return types.ListResourcesResult(resources=RESOURCES)


async def on_read_resource(
    ctx: object, params: types.ReadResourceRequestParams
) -> types.ReadResourceResult:
    return types.ReadResourceResult(
        contents=[
            types.TextResourceContents(
                uri=params.uri, mimeType="text/plain", text="CREATE TABLE orders (id int);"
            )
        ]
    )


async def on_list_prompts(
    ctx: object, params: types.PaginatedRequestParams | None
) -> types.ListPromptsResult:
    return types.ListPromptsResult(prompts=PROMPTS)


async def on_get_prompt(ctx: object, params: types.GetPromptRequestParams) -> types.GetPromptResult:
    return types.GetPromptResult(
        messages=[
            types.PromptMessage(
                role="user",
                content=types.TextContent(type="text", text="Explain the orders schema."),
            )
        ]
    )


def build() -> Server[object]:
    return Server(
        NAME,
        version=VERSION,
        instructions=INSTRUCTIONS,
        on_list_tools=on_list_tools,
        on_call_tool=on_call_tool,
        on_list_resources=on_list_resources,
        on_read_resource=on_read_resource,
        on_list_prompts=on_list_prompts,
        on_get_prompt=on_get_prompt,
    )


async def _main() -> None:
    server = build()
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(_main)
