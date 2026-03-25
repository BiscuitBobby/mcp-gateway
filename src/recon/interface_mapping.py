from browser_use import Agent, Controller
from schemas import InterfaceMap
import browser

TASK = """
You are a security researcher manually exploring an AI application to map every way a human can interact with it.
You are already on the page at {url}. {chat_location_context}

Interact with the page like a real user would:
1. Look at the main interface - identify the chat input, any buttons around it
2. Click every button you see to discover what it does - menus, attachments, settings, mode switchers
3. Expand any dropdowns or menus and explore what's inside
4. Try clicking the model selector if there is one - note all available models
5. Look for any sidebar, settings panel, or hidden menus and open them
6. Try typing a test message in the chat input to see what additional options appear
7. Note any API calls that happen as you interact

For every component you discover, note what it does and how it affects the AI.
Be thorough - a real user would click everything.
"""

async def map_interface(chat_location_context: str = "") -> InterfaceMap:
    controller = Controller(output_model=InterfaceMap)
    agent = Agent(
        task=TASK.format(url=browser.target_url, chat_location_context=chat_location_context),
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