package com.securechat.server;

import com.securechat.common.crypto.CryptoUtil;
import com.securechat.common.protocol.Packet;
import com.securechat.common.protocol.PacketType;
import com.securechat.common.util.ProtocolUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.util.*;

public class ClientHandler implements Runnable {

    private final Socket socket;
    private final ServerState serverState;

    private DataInputStream in;
    private DataOutputStream out;

    private SecretKey aesKey;
    private String username;
    private boolean running = true;

    public ClientHandler(Socket socket) {
        this.socket = socket;
        this.serverState = ServerState.getInstance();
    }

    @Override
    public void run() {
        try {
            in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

            // 1. Handshake (RSA -> AES)
            performHandshake();

            // 2. Main Loop
            while (running) {
                // Read length-prefixed packet
                byte[] encryptedData = ProtocolUtil.readPacket(in);

                // Decrypt
                byte[] packetData = CryptoUtil.decryptAES(encryptedData, aesKey);

                // Deserialize
                Packet packet = deserialize(packetData);

                // Handle Control Packets Immediately (Login, Group Mgmt)
                // Push Data Packets to Queue (DM, Group Msg, File)
                if (isControlPacket(packet)) {
                    handleControlPacket(packet);
                } else {
                    // Validate Sender
                    packet.setSender(this.username);
                    serverState.enqueue(packet);
                }
            }

        } catch (EOFException | java.net.SocketException e) {
            System.out.println("Client disconnected: " + (username != null ? username : "Unknown"));
        } catch (Exception e) {
            System.err.println("Error in ClientHandler: " + e.getMessage());
            e.printStackTrace();
        } finally {
            cleanup();
        }
    }

    private void performHandshake() throws Exception {
        // Step 1: Send RSA Public Key
        byte[] publicKeyBytes = serverState.getRsaKeyPair().getPublic().getEncoded();
        out.writeInt(publicKeyBytes.length);
        out.write(publicKeyBytes);
        out.flush();

        // Step 2: Read Encrypted AES Key
        int length = in.readInt();
        byte[] encryptedAesKey = new byte[length];
        in.readFully(encryptedAesKey);

        // Step 3: Decrypt AES Key
        byte[] aesKeyBytes = CryptoUtil.decryptRSA(encryptedAesKey, serverState.getRsaKeyPair().getPrivate());
        this.aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        System.out.println("Handshake successful. AES Key established.");
    }

    private boolean isControlPacket(Packet packet) {
        // Priority 1 usually usually reserved for control or urgent DM
        // But checking type is safer
        switch (packet.getType()) {
            case LOGIN:
            case GROUP_CREATE:
            case GROUP_JOIN:
            case GROUP_LEAVE:
            case FILE_INIT: // Handle File Init immediately to set up routing or validation
            case CHUNK_ACK: // Handle ACK immediately to update LSTCI
            case STATUS_UPDATE: // Handle status changes immediately
            case USER_LIST_QUERY: // Handle list requests immediately
            case GROUP_LIST_QUERY: // Handle group list requests immediately
                return true;
            default:
                return false;
        }
    }

    private void handleControlPacket(Packet packet) {
        switch (packet.getType()) {
            case LOGIN:
                // format: payload contains username:hashedPassword
                String loginData = new String(packet.getPayload(), java.nio.charset.StandardCharsets.UTF_8);
                String[] parts = loginData.split(":", 2);
                if (parts.length < 2) {
                    sendAuthResponse(false, "Invalid login format");
                    return;
                }
                String requestedUsername = parts[0];
                String hashedPassword = parts[1];

                if (serverState.authenticate(requestedUsername, hashedPassword)) {
                    this.username = requestedUsername;
                    serverState.addClient(requestedUsername, this);
                    serverState.setUserStatus(requestedUsername, "Online");
                    System.out.println("User logged in: " + requestedUsername);
                    sendAuthResponse(true, "Welcome");
                    broadcastUserList(); // Detailed list to everyone
                    serverState.log("System: " + username + " connected.");
                    serverState.notifyUserChange();

                    // ENHANCED: Send group list to new user immediately
                    sendAllGroupsUpdate();
                    System.out.println("[LATE_JOINER] Sent group list to " + username);
                } else {
                    sendAuthResponse(false, "Invalid password");
                }
                break;

            case GROUP_CREATE:
                String groupToCreate = packet.getGroup();
                serverState.createGroup(groupToCreate);
                serverState.joinGroup(groupToCreate, this);
                System.out.println("Group created: " + groupToCreate);
                broadcastAllGroups();
                // broadcastGlobalUserList(); // login already covers this
                break;

            case GROUP_JOIN:
                String groupToJoin = packet.getGroup();
                serverState.joinGroup(groupToJoin, this);
                System.out.println(username + " joined " + groupToJoin);
                broadcastAllGroups(); // Keep list global for everyone
                broadcastUserList(groupToJoin);
                break;

            case GROUP_LEAVE:
                String groupToLeave = packet.getGroup();
                serverState.leaveGroup(groupToLeave, this);
                broadcastAllGroups(); // Keep list global for everyone
                broadcastUserList(groupToLeave);
                break;

            case CHUNK_ACK:
                // format: packet contains fileId, chunkIndex, receiver (sender acts as receiver
                // of ACK, but logic is inverted?)
                // Actually the ACK comes FROM the Receiver TO the Sender.
                // Packet Sender = "Receiver User", Packet Receiver = "Sender User"
                // We need to look at who SENT the file.
                // The ACK packet should carry `fileId` and `chunkIndex`.
                // The `receiver` field in ACK packet is the original sender of the file.
                // The `sender` field in ACK packet is the original receiver of the file.

                // Update LSTCI: FileId -> Receiver (which is ACK sender) -> ChunkIndex
                serverState.updateLSTCI(packet.getFileId(), packet.getSender(), packet.getChunkIndex());

                System.out.println("[FLOW] " + packet.getSender() + " -> " + packet.getReceiver() + " : ACK "
                        + packet.getChunkIndex());

                // Forward ACK to original sender so they know progress
                serverState.enqueue(packet);
                break;

            case STATUS_UPDATE:
                String newStatus = new String(packet.getPayload(), java.nio.charset.StandardCharsets.UTF_8);
                serverState.setUserStatus(this.username, newStatus);
                serverState.log("System: " + this.username + " status changed to " + newStatus);
                serverState.notifyUserChange(); // Refresh server UI list
                broadcastUserList(); // Update other clients
                break;

            case RESUME_QUERY:
                // MODIFIED: Forward query to the target client instead of answering from server
                // state
                // This ensures we get the actual progress from the target device.
                String target = packet.getReceiver();
                String fileId = packet.getFileId();

                if (serverState.getGroups().containsKey(target)) {
                    // For groups, we still use the server-side LSTCI table to calculate min
                    // progress
                    // because we can't easily query ALL group members synchronously.
                    Set<String> memberNames = serverState.getGroups().get(target);
                    int minChunk = Integer.MAX_VALUE;
                    boolean foundAny = false;

                    synchronized (memberNames) {
                        for (String memberName : memberNames) {
                            int memberProgress = serverState.getLSTCI(fileId, memberName);
                            if (memberProgress != -1) {
                                minChunk = Math.min(minChunk, memberProgress);
                                foundAny = true;
                            } else {
                                minChunk = -1;
                                foundAny = true;
                                break;
                            }
                        }
                    }
                    int lastChunk = foundAny ? minChunk : -1;

                    Packet infoPacket = new Packet(PacketType.RESUME_INFO, 1);
                    infoPacket.setFileId(fileId);
                    infoPacket.setReceiver(target);
                    infoPacket.setChunkIndex(lastChunk);
                    this.sendPacket(infoPacket);
                    System.out.println("[RESUME] Responded to Group RESUME_QUERY for " + fileId + ": " + lastChunk);
                } else {
                    // For private chat, FORWARD the query to the target client
                    System.out.println("[RESUME] Forwarding RESUME_QUERY from " + username + " to " + target);
                    packet.setSender(this.username);
                    serverState.enqueue(packet);
                }
                break;

            case FILE_INIT:
                serverState.enqueue(packet);
                break;

            case FILE_CHUNK:
                System.out.println("[FLOW] " + packet.getSender() + " -> " + packet.getReceiver() + " : CHUNK "
                        + packet.getChunkIndex());
                serverState.enqueue(packet);
                break;

            case USER_LIST_QUERY:
                System.out.println("[LATE_JOINER] " + username + " requested user list");
                broadcastUserList(); // Send latest list to everyone (or just the requester, but everyone is safer
                                     // for sync)
                break;

            case GROUP_LIST_QUERY:
                System.out.println("[LATE_JOINER] " + username + " requested group list");
                sendAllGroupsUpdate(); // Send current group list to the requester
                break;

            case DM:
            case GROUP_MESSAGE:
            case GROUP_LIST_UPDATE:
            case RESUME_INFO:
            case FILE_REQ:
            case FILE_RESP:
                serverState.enqueue(packet);
                break;

            default:
                System.out.println("No handler for packet type: " + packet.getType());
                break;
        }
    }

    public void sendPacket(Packet packet) {
        try {
            // Serialize
            byte[] packetBytes = serialize(packet);

            // Encrypt
            byte[] encryptedBytes = CryptoUtil.encryptAES(packetBytes, aesKey);

            // Send
            synchronized (out) { // Ensure atomic writes
                ProtocolUtil.writePacket(out, encryptedBytes);
            }
        } catch (Exception e) {
            System.err.println("Failed to send packet to " + username + ": " + e.getMessage());
            // If we can't write, the client is dead. Cleanup.
            try {
                if (socket != null && !socket.isClosed()) {
                    serverState.log("System: Heartbeat failed for " + username + ". Disconnecting.");
                    socket.close();
                }
            } catch (IOException ex) {
                /* fast fail */ }
            // The read loop will catch SocketException and call cleanup()
        }
    }

    private void sendAuthResponse(boolean success, String message) {
        Packet p = new Packet(PacketType.AUTH_RESPONSE, 1);
        String payload = (success ? "SUCCESS" : "FAIL") + ":" + message;
        p.setPayload(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        sendPacket(p);
    }

    private void broadcastUserList() {
        Map<String, String> statusMap = serverState.getAllUserStatuses();

        // Build payload: "User1:Status|User2:Status"
        String payload = statusMap.entrySet().stream()
                .map(e -> e.getKey() + ":" + e.getValue())
                .collect(java.util.stream.Collectors.joining("|"));

        System.out.println("[LATE_JOINER] Broadcasting user list to " + serverState.getConnectedUsers().size()
                + " clients: " + payload);

        Packet listPacket = new Packet(PacketType.USER_LIST, 2);
        listPacket.setPayload(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        for (ClientHandler handler : serverState.getConnectedUsers().values()) {
            handler.sendPacket(listPacket);
        }
    }

    public void forceDisconnect() {
        try {
            running = false;
            if (socket != null && !socket.isClosed()) {
                // Optionally send a final packet to inform the client
                Packet kickPacket = new Packet(PacketType.DM, 1);
                kickPacket.setSender("System");
                kickPacket.setPayload("You have been disconnected because your account logged in from another location."
                        .getBytes(java.nio.charset.StandardCharsets.UTF_8));
                sendPacket(kickPacket);

                socket.close();
            }
        } catch (IOException e) {
            // ignore cleanup errors
        }
    }

    private void cleanup() {
        if (username != null) {
            serverState.removeClient(username, this);
            broadcastUserList(); // Update everyone else
            serverState.log("System: " + username + " disconnected.");
            serverState.notifyUserChange();
        }
        try {
            socket.close();
        } catch (IOException e) {
            // ignore
        }
    }

    // Java Serialization Helper
    private byte[] serialize(Packet packet) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(packet);
        return bos.toByteArray();
    }

    private Packet deserialize(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return (Packet) ois.readObject();
    }

    public String getUsername() {
        return username;
    }

    private void sendAllGroupsUpdate() {
        if (username == null)
            return;
        Set<String> allGroups = serverState.getGroups().keySet();
        String payload = String.join(",", allGroups);

        System.out.println("[LATE_JOINER] Sending groups to " + username + ": " + payload);

        Packet updatePacket = new Packet(PacketType.GROUP_LIST_UPDATE, 1);
        updatePacket.setReceiver(username);
        updatePacket.setPayload(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        sendPacket(updatePacket);
    }

    private void broadcastAllGroups() {
        Set<String> allGroups = serverState.getGroups().keySet();
        String payload = String.join(",", allGroups);

        System.out.println("[LATE_JOINER] Broadcasting groups to all clients: " + payload);

        Packet updatePacket = new Packet(PacketType.GROUP_LIST_UPDATE, 1);
        updatePacket.setPayload(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        for (ClientHandler client : serverState.getConnectedUsers().values()) {
            client.sendPacket(updatePacket);
        }
    }

    private void broadcastUserList(String groupName) {
        // Keeping this for group-specific context if needed later,
        // but transitioning main view to global list as requested.
        Set<String> memberNames = serverState.getGroups().get(groupName);
        if (memberNames == null)
            return;

        List<String> usernames = new ArrayList<>();
        synchronized (memberNames) {
            usernames.addAll(memberNames);
        }

        String payload = String.join(",", usernames);
        Packet updatePacket = new Packet(PacketType.USER_LIST_UPDATE, 1);
        updatePacket.setGroup(groupName);
        updatePacket.setPayload(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        synchronized (memberNames) {
            for (String memberName : memberNames) {
                ClientHandler member = serverState.getConnectedUsers().get(memberName);
                if (member != null) {
                    member.sendPacket(updatePacket);
                }
            }
        }
    }
}
