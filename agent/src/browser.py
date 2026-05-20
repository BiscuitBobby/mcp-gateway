# from browser_use import BrowserSession, ChatBrowserUse

# STORAGE_STATE = "auth.json"
# llm = ChatBrowserUse(model="bu-2-0")
# ready = False
# target_url = ""
# target_name = ""
# instance = None
# session_id = None


# async def start(url: str, name: str = ""):
#     global target_url, target_name, instance, session_id
#     from datetime import datetime, timezone

#     target_url = url
#     target_name = name or "Target"
#     session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

#     stealth_args = [
#         "--remote-allow-origins=*",
#         # Hide automation fingerprints
#         "--disable-blink-features=AutomationControlled",
#         "--disable-infobars",
#         "--disable-dev-shm-usage",
#         "--no-sandbox",
#         "--disable-setuid-sandbox",
#         # Make window geometry realistic
#         "--window-size=1280,960",
#         "--start-maximized",
#         # Avoid detection via font/canvas fingerprinting
#         "--disable-features=IsolateOrigins,site-per-process",
#         "--disable-web-security",
#         # Suppress "Chrome is being controlled by automated software" banner
#         "--disable-extensions",
#         "--disable-automation",
#     ]

#     instance = BrowserSession(
#         storage_state=STORAGE_STATE,
#         headless=True,
#         keep_alive=True,
#         args=stealth_args,
#         # Spoof a real desktop Chrome user-agent (update version periodically)
#         user_agent=(
#             "Mozilla/5.0 (X11; Linux x86_64) "
#             "AppleWebKit/537.36 (KHTML, like Gecko) "
#             "Chrome/124.0.0.0 Safari/537.36"
#         ),
#         viewport={"width": 1280, "height": 960},
#     )
#     await instance.start()

#     page = await instance.get_current_page()
#     if page is None:
#         context = await instance.browser_context
#         page = await context.new_page()

#     await page.goto(url)


# async def confirm():
#     global ready
#     if instance.session_manager is None:
#         await instance.start()
#     await instance.export_storage_state(STORAGE_STATE)
#     ready = True


# async def stop():
#     global ready
#     ready = False
#     await instance.stop()

from browser_use import BrowserSession
from models.llm_clients import browser_llm, BROWSER_STORAGE_STATE
from pathlib import Path
import json

# Export llm for backward compatibility
llm = browser_llm

ready = False
target_url = ""
target_name = ""
instance = None
session_id = None


async def start(url: str, name: str = ""):
    global target_url, target_name, instance, session_id
    from datetime import datetime, timezone

    target_url = url
    target_name = name or "Target"
    session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    stealth_args = [
        "--remote-allow-origins=*",
        # Hide automation fingerprints
        "--disable-blink-features=AutomationControlled",
        "--disable-infobars",
        "--disable-dev-shm-usage",
        "--no-sandbox",
        "--disable-setuid-sandbox",
        # Make window geometry realistic
        "--window-size=1280,960",
        "--start-maximized",
        # Avoid detection via font/canvas fingerprinting
        "--disable-features=IsolateOrigins,site-per-process",
        "--disable-web-security",
        # Suppress "Chrome is being controlled by automated software" banner
        "--disable-extensions",
        "--disable-automation",
    ]

    # Check if we have a saved auth state
    storage_state_arg = None
    if Path(BROWSER_STORAGE_STATE).exists():
        try:
            with open(BROWSER_STORAGE_STATE, "r") as f:
                state = json.load(f)
                if state.get("cookies"):
                    print(
                        f"✓ Loading saved authentication state with {len(state['cookies'])} cookies"
                    )
                    storage_state_arg = BROWSER_STORAGE_STATE
                else:
                    print("⚠ Saved auth state has no cookies, starting fresh")
        except Exception as e:
            print(f"⚠ Could not load saved auth state: {e}, starting fresh")
    else:
        print("ℹ No saved authentication state found, starting fresh session")

    instance = BrowserSession(
        storage_state=storage_state_arg,  # Only use if valid
        # headless=True,
        keep_alive=True,
        args=stealth_args,
        # Spoof a real desktop Chrome user-agent (update version periodically)
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        viewport={"width": 1280, "height": 960},
    )
    await instance.start()
    page = await instance.get_current_page()
    if page is None:
        context = await instance.browser_context
        page = await context.new_page()
    await page.goto(url)


async def confirm():
    """Save the current browser authentication state"""
    global ready
    if instance.session_manager is None:
        await instance.start()

    # Export storage state (cookies, localStorage, etc.)
    await instance.export_storage_state(BROWSER_STORAGE_STATE)

    # Verify the auth state was saved successfully
    if Path(BROWSER_STORAGE_STATE).exists():
        try:
            with open(BROWSER_STORAGE_STATE, "r") as f:
                state = json.load(f)
                # Check if we have cookies (indicates successful auth capture)
                if state.get("cookies"):
                    print(
                        f"✓ Authentication state saved with {len(state['cookies'])} cookies"
                    )
                    ready = True
                else:
                    print("⚠ Warning: No cookies found in saved state")
                    ready = False
        except Exception as e:
            print(f"⚠ Warning: Could not validate saved auth state: {e}")
            ready = False
    else:
        print(f"⚠ Warning: Auth state file not created at {BROWSER_STORAGE_STATE}")
        ready = False


async def stop():
    global ready
    ready = False
    await instance.stop()


async def clear_auth():
    """Clear saved authentication state"""
    global ready
    ready = False
    if Path(BROWSER_STORAGE_STATE).exists():
        try:
            Path(BROWSER_STORAGE_STATE).unlink()
            print(f"✓ Cleared authentication state from {BROWSER_STORAGE_STATE}")
        except Exception as e:
            print(f"⚠ Could not clear auth state: {e}")
    else:
        print("ℹ No authentication state to clear")
