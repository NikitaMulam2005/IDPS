import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "server:app",  # replace 'main' with your filename
        host="0.0.0.0",
        port=8000,  # set your desired port here
        reload=True
    )
