from browser_use import BrowserSession, ChatBrowserUse

STORAGE_STATE = "auth.json"
llm = ChatBrowserUse(model="bu-2-0")
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

    instance = BrowserSession(
        storage_state=STORAGE_STATE,
        headless=True,
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
    global ready
    if instance.session_manager is None:
        await instance.start()
    await instance.export_storage_state(STORAGE_STATE)
    ready = True


async def stop():
    global ready
    ready = False
    await instance.stop()
