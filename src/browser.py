from browser_use import BrowserSession, ChatBrowserUse

STORAGE_STATE = "auth.json"
llm = ChatBrowserUse()
ready = False
target_url = ""
target_name = ""
instance = None


async def start(url: str, name: str = ""):
    global target_url, target_name, instance
    target_url = url
    target_name = name or "Target"

    instance = BrowserSession(
        storage_state=STORAGE_STATE, keep_alive=True, args=["--remote-allow-origins=*"]
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
