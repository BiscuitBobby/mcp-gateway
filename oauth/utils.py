from urllib.parse import urlparse, urlencode, parse_qs
from oauth.models import load_oauth_state
import requests
import secrets
import hashlib
import base64


def generate_pkce_pair():
    """Generate PKCE code_verifier and code_challenge."""
    code_verifier = base64.urlsafe_b64encode(
        secrets.token_bytes(32)
    ).decode('utf-8').rstrip('=')
    
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode('utf-8')).digest()
    ).decode('utf-8').rstrip('=')
    
    return code_verifier, code_challenge


def get_authorization_server(resource_url, authorization_header):
    """Get authorization server from protected resource metadata."""
    parsed = urlparse(resource_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path
    
    well_known_url = f"{origin}/.well-known/oauth-protected-resource{path}"
    
    response = requests.get(
        well_known_url,
        headers={'Authorization': authorization_header}
    )
    response.raise_for_status()
    
    metadata = response.json()
    return metadata['authorization_servers'][0]


def get_authorization_server_metadata(auth_server_url):
    """Get OAuth authorization server metadata."""
    parsed = urlparse(auth_server_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path
    
    metadata_url = f"{origin}/.well-known/oauth-authorization-server{path}"
    
    response = requests.get(metadata_url)
    response.raise_for_status()
    
    return response.json()


def encode_token_endpoint(token_endpoint):
    """Encode token endpoint for use in URL path."""
    # Base64 encode the token endpoint to make it URL-safe
    encoded = base64.urlsafe_b64encode(token_endpoint.encode('utf-8')).decode('utf-8').rstrip('=')
    return encoded


def register_client(registration_endpoint, redirect_uris, client_name):
    """Register OAuth client at the registration endpoint."""
    registration_data = {
        "redirect_uris": redirect_uris,
        "client_name": client_name
    }
    
    response = requests.post(
        registration_endpoint,
        json=registration_data,
        headers={'Content-Type': 'application/json'}
    )
    response.raise_for_status()
    
    return response.json()


def complete_oauth_registration(resource_url, authorization_header, 
                                base_redirect_uri, client_name):
    """Complete OAuth client registration flow."""
    auth_server_url = get_authorization_server(resource_url, authorization_header)
    print(f"Authorization Server: {auth_server_url}")
    
    metadata = get_authorization_server_metadata(auth_server_url)
    print(f"Registration Endpoint: {metadata['registration_endpoint']}")
    print(f"Token Endpoint: {metadata['token_endpoint']}")
    
    # Encode token endpoint and create redirect URI with it
    encoded_token_endpoint = encode_token_endpoint(metadata['token_endpoint'])
    redirect_uri_with_token = f"{base_redirect_uri}/{encoded_token_endpoint}"
    
    print(f"\nRedirect URI: {redirect_uri_with_token}")
    
    client_info = register_client(
        metadata['registration_endpoint'],
        [redirect_uri_with_token],
        client_name
    )
    
    # Store the original token endpoint for reference
    client_info['token_endpoint'] = metadata['token_endpoint']
    client_info['authorization_endpoint'] = metadata['authorization_endpoint']
    
    return client_info


def build_authorization_url(client_id, authorization_endpoint, redirect_uri, code_challenge):
    """Build OAuth authorization URL."""
    print(f"\nClient ID:\n{client_id}\n")

    base_url = authorization_endpoint

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }

    authorization_url = f"{base_url}?{urlencode(params)}"
    
    return authorization_url


def exchange_code_for_token(authorization_code, code_verifier, client_id, 
                            client_secret, redirect_uri, token_endpoint):
    """Exchange authorization code for access token."""
    token_data = {
        "grant_type": "authorization_code",
        "code": authorization_code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier
    }
    
    if client_secret:
        token_data["client_secret"] = client_secret
    
    response = requests.post(
        token_endpoint,
        data=token_data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    response.raise_for_status()
    
    return response.json()


def handle_callback(callback_url, code_verifier, client_id, client_secret, redirect_uri):
    """
    Handle OAuth callback and exchange code for token.
    
    Args:
        callback_url: The full callback URL received from the authorization server
        code_verifier: PKCE code verifier
        client_id: OAuth client ID
        client_secret: OAuth client secret (optional)
        redirect_uri: The redirect URI used in authorization
    
    Returns:
        Token response dictionary
    """
    # Parse the callback URL
    parsed = urlparse(callback_url)
    query_params = parse_qs(parsed.query)
    
    # Extract authorization code
    if 'code' not in query_params:
        raise ValueError("Authorization code not found in callback URL")
    
    authorization_code = query_params['code'][0]
    
    # Extract and decode token endpoint from path
    # Path format: /callback/{encoded_token_endpoint}
    path_parts = parsed.path.strip('/').split('/')
    if len(path_parts) < 2:
        raise ValueError("Token endpoint not found in callback URL path")
    
    encoded_token_endpoint = path_parts[-1]
    token_endpoint = decode_token_endpoint(encoded_token_endpoint)
    
    print(f"\nExtracted authorization code: {authorization_code}")
    print(f"Decoded token endpoint: {token_endpoint}")
    
    # Exchange code for token
    token_response = exchange_code_for_token(
        authorization_code,
        code_verifier,
        client_id,
        client_secret,
        redirect_uri,
        token_endpoint
    )
    
    return token_response


def run_oauth_flow(resource_url, auth_header, base_redirect_uri, client_name):
    # Step 1: Generate PKCE parameters
    code_verifier, code_challenge = generate_pkce_pair()
    print(f"Code Verifier: {code_verifier}")
    print(f"Code Challenge: {code_challenge}\n")
    
    # Step 2: Register client
    client_info = complete_oauth_registration(
        resource_url,
        auth_header,
        base_redirect_uri,
        client_name
    )
    
    print("\nRegistered Client Info:")
    print(client_info)
    
    # Step 3: Build authorization URL
    auth_url = build_authorization_url(
        client_info["client_id"],
        client_info['authorization_endpoint'],
        client_info["redirect_uris"][0],
        code_challenge
    )
    
    # Step 4: Prepare state to pass to callback handler
    oauth_state = {
        "code_verifier": code_verifier,
        "client_id": client_info["client_id"],
        "client_secret": client_info.get("client_secret"),
        "redirect_uri": client_info["redirect_uris"][0],
        "token_endpoint": client_info["token_endpoint"]
    }
    
    return auth_url, oauth_state


# -------------------------
# Callback utils
# -------------------------
def decode_token_endpoint(encoded_endpoint: str) -> str:
    padding = 4 - (len(encoded_endpoint) % 4)
    if padding != 4:
        encoded_endpoint += "=" * padding

    return base64.urlsafe_b64decode(encoded_endpoint).decode("utf-8")


def exchange_token(alias: str,auth_code: str, token_endpoint: str):
    oauth_state = load_oauth_state(alias)

    token_data = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": oauth_state.redirect_uri,
        "client_id": oauth_state.client_id,
        "code_verifier": oauth_state.code_verifier,
    }

    if oauth_state.client_secret:
        token_data["client_secret"] = oauth_state.client_secret

    response = requests.post(
        token_endpoint,
        data=token_data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
    )

    response.raise_for_status()
    token_response = response.json()


    return token_response
