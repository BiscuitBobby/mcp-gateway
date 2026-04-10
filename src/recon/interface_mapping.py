from browser_use import Agent, Controller
from schemas import InterfaceMap
import browser

TASK = """
You are a security researcher mapping every way a human can interact with an AI chat application.
The browser is already open and logged in at {url}. Do not navigate away. Do not try to log in.

Your job is to explore what is already on screen:
1. Identify the chat input and any buttons around it
2. Click every button you see — menus, attachments, settings, mode switchers
3. Expand any dropdowns or menus and explore what's inside
4. Try clicking the model selector if there is one — note all available models
5. Look for any sidebar, settings panel, or hidden menus and open them
6. Type a test message in the chat input to see what additional options appear
7. Note any API calls that happen as you interact
8. Look for non-text input support: image upload buttons, audio/voice input,
   document/PDF attachment, URL or link fields. Check file upload dialogs for accepted MIME types.

For supported_modalities: always include "text", plus "image" if images can be uploaded or pasted,
"audio" if voice/audio input exists, "document" if PDFs/docs are accepted, "url" if URLs can be submitted.

If you see a login screen, do NOT try to log in and do NOT give up — the page has not finished loading.
Wait 2 seconds and check again. The session is active.
"""


async def map_interface(chat_location_context: str = "") -> InterfaceMap:
    controller = Controller(output_model=InterfaceMap)
    agent = Agent(
        task=TASK.format(url=browser.target_url),
        llm=browser.llm,
        browser_session=browser.instance,
        controller=controller,
    )
    history = await agent.run(max_steps=20)
    result = history.final_result()

    if isinstance(result, InterfaceMap):
        return result
    if isinstance(result, str):
        return InterfaceMap.model_validate_json(result)
    return InterfaceMap.model_validate(result)
