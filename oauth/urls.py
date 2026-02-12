from oauth.views import resolve_oauth, oauth_callback
from fastapi import APIRouter

router = APIRouter(tags=["oauth"])

router.add_api_route(
    "/resolve-oauth",
    resolve_oauth,
    methods=["GET"],
)

router.add_api_route(
    "/callback/{alias}/{encoded_token_endpoint}",
    oauth_callback,
    methods=["GET"],
)
