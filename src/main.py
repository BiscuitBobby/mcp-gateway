from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv
from fastapi import FastAPI
from routes import session
import uvicorn
import os

load_dotenv()

app = FastAPI(title="AI Red-Teaming Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(session.router)

# Serve static files
current_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(current_dir, "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
async def root():
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/{page}")
async def serve_page(page: str):
    file_path = os.path.join(static_dir, page)
    if os.path.exists(file_path):
        return FileResponse(file_path)
    return {"error": "Not Found"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)