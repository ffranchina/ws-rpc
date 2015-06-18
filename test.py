import websocket


def somma(a, b):
    return a + b


wss = websocket.WebSocketServer(port=12345)
wss.register('somma', somma)
wss.start()
