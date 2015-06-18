# versione 0.5

import socket
import threading
import hashlib
import base64
import json


class BadWSRequest(Exception):
    pass

class BadWSFrame(Exception):
    pass

class BadCmdCall(Exception):
    pass

class BadCmdParam(Exception):
    pass


class Client(threading.Thread):

    _MAGIC_STRING = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
    
    _OPCODE_TEXT = 0x1
    _OPCODE_CLOSE = 0x8

    def __init__(self, Manager, socket, address):
        super().__init__()

        self.Manager = Manager
        self.socket = socket
        self.ip, self.port = address
        self.invokedPath = None
        self.sessionStarted = False


    def _parseHeader(self):
        self.socket.settimeout(2.0)

        rcvBuffer = ''
        toRead = True
        while toRead:
            rcvBuffer += self.socket.recv(128).decode('utf-8')
            #Check for the termination sequence
            if rcvBuffer[-4:] == '\r\n\r\n': toRead = False

        #vedere di usare splitlines
        headerLines = rcvBuffer.split('\r\n')
        requestLineElements = headerLines[0].split(' ')
        if requestLineElements[0] == 'GET' and requestLineElements[-1] == 'HTTP/1.1':
            self.invokedPath = requestLineElements[2]
        else:
            raise BadWSRequest

        self.headerDict = {}
        #Cut off rubbish (first line and termination sequence)
        for header in headerLines[1:-2]:
            headerKey, headerVal = header.split(':', 1)
            self.headerDict.update({ headerKey: headerVal.strip() })

        if (
            'upgrade' not in self.headerDict['Connection'].lower().split(', ') or
            self.headerDict['Upgrade'].lower() != 'websocket' or
            'Sec-WebSocket-Key' not in self.headerDict
            #Very weak part
        ):
            raise BadWSRequest

        #Operative mode needs more time
        self.socket.settimeout(3600.0)


    def _initComunication(self):
        payload = 'HTTP/1.1 101 Web Socket Protocol Handshake\r\n'
        payload += 'Upgrade: WebSocket\r\n'
        payload += 'Connection: Upgrade\r\n'

        #Generate the security key
        acceptKey = self.headerDict['Sec-WebSocket-Key'] + self._MAGIC_STRING
        acceptKey = hashlib.sha1( acceptKey.encode('ascii') ).digest()
        acceptKey = base64.b64encode(acceptKey)

        payload += 'Sec-WebSocket-Accept: ' + acceptKey.decode('utf-8') + '\r\n\r\n'

        self.socket.send( payload.encode('utf-8') )


    def _rcvRequest(self):
        #1st byte: FIN, RUBBISH1, RUBBISH2, RUBBISH3, OPCODE (4 bit)
        #2nd byte: MASKED, PAYLOAD_LENGTH (7 bit)
        rcvBuffer = self.socket.recv(2)
        print('FIN: ' + str( rcvBuffer[0] >> 7 ))

        #0x0f is 00001111 binary sequence
        opcode = rcvBuffer[0] & 0x0f
        print('opcode: ' + hex( opcode ))
        maskBit = rcvBuffer[1] >> 7
        print('mask: ' + str( maskBit ))

        if maskBit != 1:
            raise BadWSFrame('Unmasked data')

        #0x7f is 01111111 binary sequence
        length = rcvBuffer[1] & 0x7f
        if length == 126:
            #A long length is stored in more space
            rcvBuffer = self.socket.recv(2)
            length = int.from_bytes(rcvBuffer, 'big')
            
        elif length == 127:
            #un carico maggiore di 65kb a thread mi fa collassare il tutto..
            #Ma poi.. perche' un utente dovrebbe caricare cosi' tanti dati? :O
            raise BadWSFrame('Too big payload')

        print('length: ' + str(length))

        #Read the mask applied to data
        maskKey = self.socket.recv(4)
        
        #valutare di bufferizzare per rendere il thread piu' parsionioso
        rcvBuffer = self.socket.recv(length)
        message = b''
        for i in range(length):
            #Unmask the original message
            message += bytes([ rcvBuffer[i] ^ maskKey[i % 4] ])
        print(message)
        
        if opcode == self._OPCODE_TEXT:
            return json.loads( message.decode('utf-8') )
        elif opcode == self._OPCODE_CLOSE:
            return None
        else:
            raise BadWSFrame('Unknown OpCode')


    def _sndResponse(self, data):
        data = json.dumps(data).encode('utf-8')
        length = len(data)

        #FIN bit and opcode 0x1 (0x81 is 10000001 binary sequence)
        payload = b'\x81'

        if length >= 65535:
            #Over the maximum length allowed by 16bit addressing
            raise BadWSFrame('Too big payload')
        elif length <= 125:
            payload += bytes([length])
        else:
            payload += bytes([126])
            payload += length.to_bytes(2, 'big')

        #si potrebbe bufferizzare l'invio
        self.socket.send(payload + data)


    #Chiudere inviando un codice di errore e usando l'opcode globale
    def _sndClose(self):
        #FIN bit and opcode 0x8 (0x88 is 10001000 binary sequence)
        #Mask and length bits are zero
        self.socket.send(b'\x88\x00')
        #Empty the remote buffer
        self.socket.recv(100)


    def run(self):
        print('[+] Connection established with ' + self.ip + ':' + str(self.port), "[%s]" % str(len(self.Manager)))
        try:
            self._parseHeader()
            self._initComunication()
            self.sessionStarted = True

            #socket non bloccanti potrebbero essere di aiuto per smaltire prima i dati
            while True:
                request = self._rcvRequest()
                if not request: break

                response = self.Manager.executeAction(self, request)
                if response == None:
                    raise UnknownCommand
                
                self._sndResponse(response)

        except BadWSRequest:
            print('[!] Bad-formed request from ' + self.ip + ':' + str(self.port))

        except BadWSFrame as err:
            print('[!] Bad-formed frame from ' + self.ip + ':' + str(self.port), str(err))
            #valutare se lasciare il messaggio o meno

        except BadCmdCall as err:
            print('[!] Unknown command received from ' + self.ip + ':' + str(self.port), str(err))

        except BadCmdParam as err:
            print('[!] Invalid parameters from ' + self.ip + ':' + str(self.port), str(err))

        except socket.timeout:
            print('[!] Timeout occurred for ' + self.ip + ':' + str(self.port))

        finally:
            if self.sessionStarted:
                self._sndClose()
                
            self.socket.close()
            self.Manager.rmvClient(self)
            print('[-] Connection closed with ' + self.ip + ':' + str(self.port), "[%s]" % str(len(self.Manager)))



class ClientManager:

    def __init__(self):
        self.clientList = []
        self.actionDict = {}


    def __len__(self):
        return len(self.clientList)


    def addClient(self, clientSocket, address):
        newClient = Client(self, clientSocket, address)
        newClient.start()
        self.clientList.append(newClient)


    def rmvClient(self, clientInstance):
        self.clientList.remove(clientInstance)


    def registerAction(self, functionName, function):
        self.actionDict.update({ functionName: function })


    def executeAction(self, clientInstance, request):
        #Array of two element is expected
        function, parameters = request

        if function in self.actionDict:
            try:
                return self.actionDict[function](*parameters)
            except TypeError:
                raise BadCmdParam(request)
        else:
            raise BadCmdCall(function)


    def shutdown(self):
        for client in self.clientList:
            client.join()

    

class WebSocketServer:

    def __init__(self, ip = '0.0.0.0', port = 8888, conns = 9999):
        self.ip = ip
        self.port = port

        self.CM = ClientManager()
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.bind( (self.ip, self.port) )
            self.socket.listen(conns)
            print('[#] Waiting for connections on ' + self.ip + ':' + str(self.port) + '...')
            
        except socket.error as err:
            print('[!] Error opening the socket: ' + str(err))


    def register(self, functionName, function):
        self.CM.registerAction(functionName, function)


    def start(self):
        try:
            while True:
                clientSocket, address = self.socket.accept()
                self.CM.addClient(clientSocket, address)
            
        except:
            print('[#] Shutting down the server...')
            self.stop()


    def stop(self):
        self.CM.shutdown()
        self.socket.close()


