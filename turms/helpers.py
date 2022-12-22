import base64
import json
from typing import Any, Dict, Optional
from urllib import request
import glob
import graphql

from turms.config import Auth
from turms.errors import GenerationError

from graphql import (
    build_ast_schema,
    build_client_schema,
    get_introspection_query,
    parse,
)


def introspect_url(
    schema_url: str, auth: Optional[Auth] = None
) -> Dict[str, Any]:
    """Introspect a GraphQL schema using introspection query

    Args:
        schema_url (str): The Schema url
        bearer_token (str, optional): A Bearer token. Defaults to None.

    Raises:
        GenerationError: An error occurred while generating the schema.

    Returns:
        dict: The introspection query response.
    """
    jdata = json.dumps({"query": get_introspection_query()}).encode("utf-8")
    req = request.Request(schema_url, data=jdata)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    if auth and auth.bearer_token:
        req.add_header("Authorization", f"Bearer {auth.bearer_token}")
    elif auth and (auth.basic_username or auth.basic_password):
        pair = f"{auth.basic_username or ''}:{auth.basic_password or ''}".encode()
        req.add_header("Authorization", f"Basic {base64.b64encode(pair).decode()}")
    try:
        resp = request.urlopen(req)
        x = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        raise GenerationError(f"Failed to fetch schema from {schema_url}")
    if "errors" in x:  # pragma: no cover
        raise GenerationError(
            f"Failed to fetch schema from {schema_url} Graphql error: {x['errors']}"
        )
    return x["data"]


def build_schema_from_introspect_url(
    schema_url: str, auth: Optional[Auth] = None
) -> graphql.GraphQLSchema:
    """Introspect a GraphQL schema using introspection query

    Args:
        schema_url (str): The Schema url
        bearer_token (str, optional): A Bearer token. Defaults to None.

    Raises:
        GenerationError: An error occurred while generating the schema.

    Returns:
        graphql.GraphQLSchema: The parsed GraphQL schema.
    """
    x = introspect_url(schema_url, auth)

    return build_client_schema(x)


def build_schema_from_glob(glob_string: str):
    """Build a GraphQL schema from a glob string"""
    schema_glob = glob.glob(glob_string, recursive=True)
    dsl_string = ""
    introspection_string = ""
    for file in schema_glob:
        with open(file, "rb") as f:
            decoded_file = f.read().decode("utf-8-sig")
            if file.endswith(".graphql"):
                dsl_string += decoded_file
            elif file.endswith(".json"):
                # not really necessary as json files are generally not splitable
                introspection_string += decoded_file

    if not dsl_string and not introspection_string:
        raise GenerationError(f"No schema files found in {glob_string}")

    if dsl_string != "" and introspection_string != "":  # pragma: no cover
        raise GenerationError("We cannot have both dsl and introspection files")
    if dsl_string != "":
        return build_ast_schema(parse(dsl_string))
    else:
        return build_client_schema(json.loads(introspection_string))
