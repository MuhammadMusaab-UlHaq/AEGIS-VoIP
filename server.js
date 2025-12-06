/**
 * AEGIS-VoIP Signaling Server
 * WebSocket-based signaling for automatic peer connection
 */

import { WebSocketServer } from 'ws';
import { randomBytes } from 'crypto';

const PORT = process.env.PORT || 8080;
const wss = new WebSocketServer({ port: PORT });

// Store active rooms and their participants
const rooms = new Map();

function generateRoomId() {
    return randomBytes(4).toString('hex').toUpperCase();
}

function log(message) {
    console.log(`[${new Date().toISOString()}] ${message}`);
}

wss.on('connection', (ws) => {
    let clientId = null;
    let currentRoom = null;

    log('New client connected');

    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data.toString());
            
            switch (message.type) {
                case 'create-room':
                    const roomId = generateRoomId();
                    clientId = randomBytes(8).toString('hex');
                    currentRoom = roomId;
                    
                    rooms.set(roomId, {
                        creator: { ws, clientId },
                        joiner: null,
                        createdAt: Date.now()
                    });
                    
                    ws.send(JSON.stringify({
                        type: 'room-created',
                        roomId,
                        clientId
                    }));
                    
                    log(`Room ${roomId} created by ${clientId}`);
                    break;

                case 'join-room':
                    const { roomId: joinRoomId } = message;
                    const room = rooms.get(joinRoomId);
                    
                    if (!room) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Room not found'
                        }));
                        log(`Client tried to join non-existent room: ${joinRoomId}`);
                        return;
                    }
                    
                    if (room.joiner) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Room is full'
                        }));
                        log(`Client tried to join full room: ${joinRoomId}`);
                        return;
                    }
                    
                    clientId = randomBytes(8).toString('hex');
                    currentRoom = joinRoomId;
                    room.joiner = { ws, clientId };
                    
                    ws.send(JSON.stringify({
                        type: 'room-joined',
                        roomId: joinRoomId,
                        clientId
                    }));
                    
                    // Notify creator that someone joined
                    room.creator.ws.send(JSON.stringify({
                        type: 'peer-joined',
                        peerId: clientId
                    }));
                    
                    log(`Client ${clientId} joined room ${joinRoomId}`);
                    break;

                case 'offer':
                case 'answer':
                case 'ice-candidate':
                    if (!currentRoom) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Not in a room'
                        }));
                        return;
                    }
                    
                    const targetRoom = rooms.get(currentRoom);
                    if (!targetRoom) return;
                    
                    // Forward message to the other peer
                    const isCreator = targetRoom.creator.clientId === clientId;
                    const targetPeer = isCreator ? targetRoom.joiner : targetRoom.creator;
                    
                    if (targetPeer && targetPeer.ws.readyState === 1) {
                        targetPeer.ws.send(JSON.stringify({
                            ...message,
                            from: clientId
                        }));
                        log(`Forwarded ${message.type} from ${clientId} in room ${currentRoom}`);
                    }
                    break;

                case 'leave-room':
                    if (currentRoom) {
                        const leaveRoom = rooms.get(currentRoom);
                        if (leaveRoom) {
                            // Notify the other peer
                            const isCreator = leaveRoom.creator.clientId === clientId;
                            const otherPeer = isCreator ? leaveRoom.joiner : leaveRoom.creator;
                            
                            if (otherPeer && otherPeer.ws.readyState === 1) {
                                otherPeer.ws.send(JSON.stringify({
                                    type: 'peer-left'
                                }));
                            }
                            
                            rooms.delete(currentRoom);
                            log(`Room ${currentRoom} closed`);
                        }
                        currentRoom = null;
                    }
                    break;

                default:
                    log(`Unknown message type: ${message.type}`);
            }
        } catch (error) {
            log(`Error processing message: ${error.message}`);
            ws.send(JSON.stringify({
                type: 'error',
                message: 'Invalid message format'
            }));
        }
    });

    ws.on('close', () => {
        if (currentRoom) {
            const room = rooms.get(currentRoom);
            if (room) {
                // Notify the other peer
                const isCreator = room.creator.clientId === clientId;
                const otherPeer = isCreator ? room.joiner : room.creator;
                
                if (otherPeer && otherPeer.ws.readyState === 1) {
                    otherPeer.ws.send(JSON.stringify({
                        type: 'peer-left'
                    }));
                }
                
                rooms.delete(currentRoom);
                log(`Room ${currentRoom} closed due to disconnect`);
            }
        }
        log(`Client ${clientId || 'unknown'} disconnected`);
    });

    ws.on('error', (error) => {
        log(`WebSocket error: ${error.message}`);
    });
});

// Clean up old rooms every 5 minutes
setInterval(() => {
    const now = Date.now();
    const maxAge = 30 * 60 * 1000; // 30 minutes
    
    for (const [roomId, room] of rooms.entries()) {
        if (now - room.createdAt > maxAge) {
            rooms.delete(roomId);
            log(`Cleaned up stale room: ${roomId}`);
        }
    }
}, 5 * 60 * 1000);

log(`Signaling server running on port ${PORT}`);
