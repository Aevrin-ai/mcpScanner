# SPDX-License-Identifier: PolyForm-Strict-1.0.0
# Copyright (c) 2026 Aevrin. See the LICENSE and NOTICE files.
"""Models for what an MCP server tells us about itself."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


class ToolInfo(BaseModel):
    name: str
    title: str | None = None
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_wire(cls, data: dict[str, Any]) -> ToolInfo:
        """Build from the JSON a server sends. Odd or missing fields get safe defaults."""
        schema = data.get("inputSchema") or data.get("input_schema") or data.get("parameters")
        output = data.get("outputSchema")
        return cls(
            name=str(data.get("name", "")),
            title=_str_or_none(data.get("title")),
            description=str(data.get("description") or ""),
            input_schema=_dict_or_empty(schema),
            output_schema=output if isinstance(output, dict) else None,
            annotations=_dict_or_empty(data.get("annotations")),
            raw=data,
        )

    def properties(self) -> dict[str, dict[str, Any]]:
        props = self.input_schema.get("properties")
        if not isinstance(props, dict):
            return {}
        return {str(k): _dict_or_empty(v) for k, v in props.items()}

    def required(self) -> list[str]:
        value = self.input_schema.get("required")
        return [str(v) for v in value] if isinstance(value, list) else []


class PromptArgument(BaseModel):
    name: str
    description: str = ""
    required: bool = False


class PromptInfo(BaseModel):
    name: str
    title: str | None = None
    description: str = ""
    arguments: list[PromptArgument] = Field(default_factory=list)
    # Filled only by dynamic analysis (prompts/get).
    rendered_text: str | None = None

    @classmethod
    def from_wire(cls, data: dict[str, Any]) -> PromptInfo:
        args = [
            PromptArgument(
                name=str(item["name"]),
                description=str(item.get("description") or ""),
                required=bool(item.get("required", False)),
            )
            for item in data.get("arguments") or []
            if isinstance(item, dict) and item.get("name")
        ]
        return cls(
            name=str(data.get("name", "")),
            title=_str_or_none(data.get("title")),
            description=str(data.get("description") or ""),
            arguments=args,
        )


class ResourceInfo(BaseModel):
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str | None = None
    # Filled only by dynamic analysis (resources/read).
    text: str | None = None

    @classmethod
    def from_wire(cls, data: dict[str, Any]) -> ResourceInfo:
        return cls(
            uri=str(data.get("uri", "")),
            name=str(data.get("name") or ""),
            description=str(data.get("description") or ""),
            mime_type=_str_or_none(data.get("mimeType")),
        )


class ResourceTemplateInfo(BaseModel):
    uri_template: str
    name: str = ""
    description: str = ""
    mime_type: str | None = None

    @classmethod
    def from_wire(cls, data: dict[str, Any]) -> ResourceTemplateInfo:
        return cls(
            uri_template=str(data.get("uriTemplate", "")),
            name=str(data.get("name") or ""),
            description=str(data.get("description") or ""),
            mime_type=_str_or_none(data.get("mimeType")),
        )


class ServerInventory(BaseModel):
    """Everything the server listed during the scan."""

    server_name: str | None = None
    server_version: str | None = None
    protocol_version: str | None = None
    capabilities: dict[str, Any] = Field(default_factory=dict)
    instructions: str | None = None
    tools: list[ToolInfo] = Field(default_factory=list)
    prompts: list[PromptInfo] = Field(default_factory=list)
    resources: list[ResourceInfo] = Field(default_factory=list)
    resource_templates: list[ResourceTemplateInfo] = Field(default_factory=list)

    def tool(self, name: str) -> ToolInfo | None:
        return next((t for t in self.tools if t.name == name), None)
