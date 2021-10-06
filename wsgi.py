from app.main import socketio, app, mode

if __name__ == '__main__' and mode == "PRODUCTION":
    print("Running production server.")
    app.run()

elif __name__ == "__main__" and mode == "DEV":
    print("Running development server.")
    socketio.run(app, debug=True)
