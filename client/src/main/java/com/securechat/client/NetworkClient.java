package com.securechat.client;

import com.securechat.common.crypto.CryptoUtil;
import com.securechat.common.protocol.Packet;
import com.securechat.common.protocol.PacketType;
import com.securechat.common.util.FileTransferUtil;
import com.securechat.common.util.ProtocolUtil;
import javafx.application.Platform;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import java.security.PrivateKey;
import java.security.KeyPair;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;

public class NetworkClient {
    private Socket socket;
    private String lastUsername;
    private String lastPassword;
    private volatile boolean intentionallyClosed = false;
    private volatile boolean forcedDisconnect = false;
    private boolean authSuccess = false;

    private DataInputStream in;
    private DataOutputStream out;
    private SecretKey aesKey;
    private boolean running = true;
    private String myUsername;

    private final String serverIp;
    private final int serverPort;
    private volatile ClientController controller;

    public void setController(ClientController controller) {
        this.controller = controller;
    }

    // File Reassembly State: FileID -> RandomAccessFile
    private final Map<String, RandomAccessFile> activeDownloads = new ConcurrentHashMap<>();
    private final Map<String, Set<Integer>> receivedChunksCount = new ConcurrentHashMap<>();
    private final Map<String, Map<Integer, CompletableFuture<Void>>> pendingAcks = new ConcurrentHashMap<>();
    private final Map<String, ChatWindowController> activeWindows = new ConcurrentHashMap<>();

    // E2EE Management
    private final Map<String, SecretKey> e2eKeyMap = new ConcurrentHashMap<>();
    private final Map<String, PrivateKey> pendingDHKeys = new ConcurrentHashMap<>();
    private final Map<String, Queue<String>> pendingMessages = new ConcurrentHashMap<>();

    // Universal Reassembly: TransactionID -> Map<ChunkIndex, byte[]>
    private final Map<String, Map<Integer, byte[]>> incomingChunks = new ConcurrentHashMap<>();

    // Resume Coordination: FileID -> Future of lastChunkIndex
    private final Map<String, CompletableFuture<Integer>> pendingResumeRequests = new ConcurrentHashMap<>();
    private final Set<String> activeUploads = Collections.synchronizedSet(new HashSet<>());
    private CompletableFuture<String> loginFuture;

    // Permission Handshake: FileID -> Future<Boolean> (True=Approved, False=Denied)
    private final Map<String, CompletableFuture<Boolean>> pendingFileRequests = new ConcurrentHashMap<>();

    // Tracks which files we (as a receiver) have explicitly accepted.
    private final Set<String> acceptedFileTransfers = Collections.synchronizedSet(new HashSet<>());

    // Parallel Group Uploads: FileID -> AppData
    private final Map<String, File> pendingGroupUploads = new ConcurrentHashMap<>();
    private final Map<String, String> pendingGroupTransactionIds = new ConcurrentHashMap<>();

    public NetworkClient(String serverIp, int serverPort, ClientController controller) {
        this.serverIp = serverIp;
        this.serverPort = serverPort;
        this.controller = controller;
    }

    public void connect(String username) throws Exception {
        this.myUsername = username;
        socket = new Socket(serverIp, serverPort);
        in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
        out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));

        // 1. Handshake
        performHandshake();

        // 2. Start Listener Thread
        Thread listenerThread = new Thread(this::listen);
        listenerThread.setDaemon(true);
        listenerThread.start();
    }

    private void performHandshake() throws Exception {
        // Read Server RSA Public Key
        int len = in.readInt();
        byte[] pubKeyBytes = new byte[len];
        in.readFully(pubKeyBytes);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(pubKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey serverPubKey = kf.generatePublic(spec);

        // Generate and Send AES Key
        this.aesKey = CryptoUtil.generateAESKey();
        byte[] encryptedAesKey = CryptoUtil.encryptRSA(aesKey.getEncoded(), serverPubKey);

        out.writeInt(encryptedAesKey.length);
        out.write(encryptedAesKey);
        out.flush();

        System.out.println("Handshake complete.");
    }

    private void listen() {
        try {
            while (true) {
                byte[] encryptedData = ProtocolUtil.readPacket(in);
                if (encryptedData == null)
                    break; // Connection closed or error
                byte[] packetData = CryptoUtil.decryptAES(encryptedData, aesKey);
                Packet packet = deserialize(packetData);

                handlePacket(packet);
            }
        } catch (Exception e) {
            if (!intentionallyClosed && !forcedDisconnect) {
                System.err.println("Listener error: " + e.getMessage());
                if (authSuccess) {
                    attemptReconnect();
                }
            } else if (forcedDisconnect) {
                System.out.println("[INFO] Disconnected due to duplicate login. Not attempting reconnect.");
            }
        } finally {
            if (!intentionallyClosed)
                cleanup();
        }
    }

    private void attemptReconnect() {
        Thread reconnectThread = new Thread(() -> {
            while (!intentionallyClosed) {
                try {
                    Thread.sleep(3000); // Wait 3 seconds to retry
                    System.out.println("Attempting to reconnect...");
                    // Close existing resources before reconnecting
                    cleanup();
                    // Re-establish socket and handshake
                    socket = new Socket(serverIp, serverPort);
                    in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
                    out = new DataOutputStream(new BufferedOutputStream(socket.getOutputStream()));
                    performHandshake();

                    String result = login(lastUsername, lastPassword).get(25, java.util.concurrent.TimeUnit.SECONDS);
                    if (result.startsWith("SUCCESS")) {
                        System.out.println("Auto-reconnected and logged in.");
                        Platform.runLater(
                                () -> controller.appendChat("System: Connection restored. Automatic resume possible."));
                        // Restart listener and heartbeat threads
                        Thread t = new Thread(this::listen);
                        t.setDaemon(true);
                        t.start();
                        Thread h = new Thread(this::sendHeartbeat);
                        h.setDaemon(true);
                        h.start();
                        break;
                    } else {
                        // Authentication failed during reconnect - stop retrying
                        System.err.println("Reconnect failed: Authentication error.");
                        Platform.runLater(() -> controller.appendChat("System: Reconnect failed (Auth Error)."));
                        break;
                    }
                } catch (Exception e) {
                    System.err.println("Reconnection failed: " + e.getMessage());
                    Platform.runLater(() -> controller.appendChat("System: Reconnection failed. Retrying..."));
                }
            }
        });
        reconnectThread.setDaemon(true);
        reconnectThread.start();
    }

    private void cleanup() {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
            if (in != null)
                in.close();
            if (out != null)
                out.close();
        } catch (IOException e) {
            System.err.println("Error during cleanup: " + e.getMessage());
        }
    }

    private void sendHeartbeat() {
        try {
            while (running && !intentionallyClosed) {
                Thread.sleep(10000); // Send heartbeat every 10 seconds
                Packet heartbeat = new Packet(PacketType.HEARTBEAT, 0);
                sendPacket(heartbeat);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.out.println("Heartbeat thread interrupted.");
        } catch (Exception e) {
            System.err.println("Heartbeat error: " + e.getMessage());
        }
    }

    private void handlePacket(Packet packet) {
        switch (packet.getType()) {
            case DM:
            case GROUP_MESSAGE:
                String transId = packet.getTransactionId();
                if (transId == null) {
                    processFullMessage(packet);
                    break;
                }

                // Defensive Check: Max Chunks Limit (2M chunks = ~128GB at 64KB)
                if (packet.getTotalChunks() > 2000000 || packet.getTotalChunks() <= 0) {
                    System.err.println(
                            "[REASSEMBLY] Rejecting packet with suspicious chunk count: " + packet.getTotalChunks());
                    break;
                }

                // Defensive Check: Chunk Index Validation
                if (packet.getChunkIndex() < 0 || packet.getChunkIndex() >= packet.getTotalChunks()) {
                    System.err.println("[REASSEMBLY] Invalid chunk index: " + packet.getChunkIndex() + "/"
                            + packet.getTotalChunks());
                    break;
                }

                Map<Integer, byte[]> chunks = incomingChunks.computeIfAbsent(transId, k -> new ConcurrentHashMap<>());

                // Defensive Check: Consistency of totalChunks for the same transId
                // We'll use the first packet's totalChunks as the source of truth for this
                // transaction
                // (This is a bit simplified, but effective for basic integrity)

                chunks.put(packet.getChunkIndex(), packet.getPayload());

                if (chunks.size() == packet.getTotalChunks()) {
                    // All arrived!
                    incomingChunks.remove(transId);

                    // Reassemble
                    ByteArrayOutputStream reassembled = new ByteArrayOutputStream();
                    boolean integrityFail = false;
                    for (int i = 0; i < packet.getTotalChunks(); i++) {
                        byte[] c = chunks.get(i);
                        if (c != null) {
                            reassembled.write(c, 0, c.length);
                        } else {
                            integrityFail = true;
                            break;
                        }
                    }

                    if (integrityFail) {
                        System.err.println("[REASSEMBLY] Failed to reassemble " + transId + " due to missing chunks.");
                    } else {
                        packet.setPayload(reassembled.toByteArray());
                        System.out.println("[REASSEMBLY] Completed message for transaction " + transId + " ("
                                + packet.getTotalChunks() + " chunks)");
                        processFullMessage(packet);

                        // Send ACKs for Direct and Group Messages
                        if (packet.getType() == PacketType.DM || packet.getType() == PacketType.GROUP_MESSAGE) {
                            PacketType ackType = (packet.getType() == PacketType.DM) ? PacketType.DM_ACK
                                    : PacketType.GROUP_ACK;
                            Packet ack = new Packet(ackType, 1);
                            ack.setSender(myUsername);
                            ack.setReceiver(packet.getSender()); // Send directly back to sender
                            ack.setGroup(packet.getGroup()); // Include group context if applicable
                            ack.setTransactionId(transId);
                            ack.setTotalChunks(packet.getTotalChunks());
                            sendPacket(ack);
                        }
                    }
                }
                break;

            case GROUP_LIST_UPDATE:
                String listPayload = new String(packet.getPayload(), java.nio.charset.StandardCharsets.UTF_8);
                String[] groups = listPayload.split(",");
                if (controller != null) {
                    controller.updateGroupList(groups);
                }
                break;

            case FILE_INIT: {
                if (packet.getGroup() != null) {
                    // Check if we accepted this file
                    if (!acceptedFileTransfers.contains(packet.getFileId())) {
                        System.out.println("[FILTER] Ignoring un-accepted group file: " + packet.getFileName());
                        return;
                    }
                }

                String context = (packet.getGroup() != null) ? "Group " + packet.getGroup() : "Private Chat";
                String targetKey = (packet.getGroup() != null) ? packet.getGroup() : packet.getSender();
                String senderName = (packet.getSender() != null) ? packet.getSender() : "Someone";

                Platform.runLater(() -> {
                    ChatWindowController chatWin = activeWindows.get(targetKey);
                    if (chatWin != null) {
                        chatWin.appendChatMessage("System: Receiving file '" + packet.getFileName() + "' from "
                                + senderName + " in " + context);
                    } else {
                        controller.appendChat("System: Receiving file '" + packet.getFileName() + "' from " + senderName
                                + " in " + context + " (Open chat to see progress)");
                    }
                });
                try {
                    File downloadDir = new File("downloads");
                    if (!downloadDir.exists())
                        downloadDir.mkdir();

                    File file = new File(downloadDir, packet.getFileName() + ".part");
                    RandomAccessFile raf = new RandomAccessFile(file, "rw");

                    // Integrity Fix: If the existing partial file is LARGER than the new file (e.g.
                    // from an old download),
                    // we must truncate the tail to avoid checksum mismatches due to garbage data at
                    // the end.
                    if (raf.length() > packet.getFileSize()) {
                        System.out.println("[INTEGRITY] Truncating '" + file.getName() + "' from " + raf.length()
                                + " to " + packet.getFileSize());
                        raf.setLength(packet.getFileSize());
                    }

                    activeDownloads.put(packet.getFileId(), raf);
                    System.out.println("System: Started receiving file " + packet.getFileName());
                } catch (Exception e) {
                    System.err.println("ERROR: Failed to initialize file download!");
                    e.printStackTrace();
                    Platform.runLater(() -> controller.appendChat("System: ERROR - Cannot save file! Check console."));
                }
                break;
            }

            case FILE_CHUNK: {
                try {
                    String fileId = packet.getFileId();

                    // FILTER: If this is a group chunk and we typically don't track it, IGNORE IT.
                    // However, we only have activeDownloads if FILE_INIT passed.
                    // But if we joined LATE (sending Auto-Recovery), we must also check permission.
                    if (packet.getGroup() != null && !acceptedFileTransfers.contains(fileId)) {
                        return; // Silent Drop
                    }

                    RandomAccessFile raf = activeDownloads.get(fileId);

                    if (raf == null) {
                        System.out.println("[RECOVERY] Received mid-transfer chunk for unknown fileId: " + fileId
                                + ". Attempting auto-recovery...");
                        // Receiver Auto-Recovery: Missing FILE_INIT (happens after reconnection)
                        File downloadDir = new File("downloads");
                        if (!downloadDir.exists())
                            downloadDir.mkdir();

                        File file = new File(downloadDir, packet.getFileName() + ".part");
                        raf = new RandomAccessFile(file, "rw");
                        activeDownloads.put(fileId, raf);

                        String recoveryContext = (packet.getGroup() != null) ? "Group " + packet.getGroup()
                                : "Private Chat";
                        Platform.runLater(() -> {
                            controller.appendChat("System: Resuming reception of '" + packet.getFileName() + "' in "
                                    + recoveryContext + " (.part mode)");
                        });
                    }

                    if (raf != null) {
                        raf.seek((long) packet.getChunkIndex() * FileTransferUtil.CHUNK_SIZE);
                        raf.write(packet.getPayload());
                        raf.getFD().sync(); // Force persistence to prevent corruption on crash/flicker

                        // Track unique chunks
                        receivedChunksCount.computeIfAbsent(fileId, k -> Collections.synchronizedSet(new HashSet<>()))
                                .add(packet.getChunkIndex());

                        // Send ACK (Now includes total chunks for progress tracking)
                        Packet ack = new Packet(PacketType.CHUNK_ACK, 1);
                        ack.setFileId(fileId);
                        ack.setChunkIndex(packet.getChunkIndex());
                        ack.setTotalChunks(packet.getTotalChunks());
                        ack.setSender(myUsername);
                        ack.setReceiver(packet.getSender());

                        System.out.println(
                                "[FLOW] Sending CHUNK_ACK for chunk " + packet.getChunkIndex() + " of file " + fileId);
                        sendPacket(ack);

                        int uniqueCount = receivedChunksCount.get(fileId).size();
                        if (uniqueCount == packet.getTotalChunks()) {
                            raf.close();
                            activeDownloads.remove(fileId);
                            receivedChunksCount.remove(fileId);
                            String fileKey = (packet.getGroup() != null) ? packet.getGroup() : packet.getSender();
                            Platform.runLater(() -> {
                                ChatWindowController chatWin = activeWindows.get(fileKey);
                                if (chatWin != null) {
                                    chatWin.appendChatMessage("System: File download complete: " + packet.getFileName()
                                            + " (Saved to ./downloads folder)");
                                } else {
                                    controller.appendChat("System: File download complete: " + packet.getFileName()
                                            + " (Saved to ./downloads folder)");
                                }
                            });
                        }
                    }
                } catch (IOException e) {
                    System.err.println("[RECOVERY] Error during file write or recovery: " + e.getMessage());
                    e.printStackTrace();
                }
                break;
            }

            case AUTH_RESPONSE:
                if (loginFuture != null) {
                    String resp = new String(packet.getPayload(), java.nio.charset.StandardCharsets.UTF_8);
                    if (resp.startsWith("SUCCESS")) {
                        authSuccess = true;
                    }
                    loginFuture.complete(resp);
                }
                break;
            case USER_LIST_UPDATE:
            case USER_LIST:
                String userPayload = new String(packet.getPayload(), java.nio.charset.StandardCharsets.UTF_8);
                // Robust parsing: split by pipe, ignore commas which were legacy
                String[] users = userPayload.split("\\|");

                if (controller != null) {
                    controller.updateUserList(users);
                }
                break;

            case KEY_EXCHANGE:
                handleKeyExchange(packet);
                break;

            case DM_ACK:
            case GROUP_ACK:
                String ackSender = packet.getSender();
                String targetWindow = (packet.getType() == PacketType.DM_ACK) ? ackSender : packet.getGroup();
                Platform.runLater(() -> {
                    ChatWindowController chatWin = activeWindows.get(targetWindow);
                    if (chatWin != null) {
                        String statusMsg = (packet.getType() == PacketType.DM_ACK)
                                ? "System: Message Delivered ✓"
                                : "System: Delivered to " + ackSender + " ✓";
                        chatWin.appendChatMessage(statusMsg);
                    } else if (packet.getType() == PacketType.DM_ACK) {
                        controller.appendChat("System: Send confirmation received from " + ackSender);
                    }
                });
                break;

            case RESUME_INFO: {
                String fid = packet.getFileId();
                String sender = packet.getSender(); // This is the person who answered our query
                String trackingKey = fid + "_" + sender;

                System.out.println("[DEBUG] Received RESUME_INFO for trackingKey: " + trackingKey + ", chunk: "
                        + packet.getChunkIndex());
                if (fid != null && pendingResumeRequests.containsKey(trackingKey)) {
                    pendingResumeRequests.get(trackingKey).complete(packet.getChunkIndex());
                    System.out.println("[DEBUG] Completed future for trackingKey: " + trackingKey);
                } else {
                    System.out.println("[DEBUG] Ignored RESUME_INFO (No pending request for " + trackingKey + ")");
                }
                break;
            }
            case LOGIN:
            case GROUP_CREATE:
            case GROUP_JOIN:
            case GROUP_LEAVE:
            case CHUNK_ACK:
                String fileIdForAck = packet.getFileId();
                int idx = packet.getChunkIndex();
                String senderOfAck = packet.getSender(); // Should be the receiver of the file

                System.out.println("[FLOW] Received CHUNK_ACK for file " + fileIdForAck + ", chunk " + idx + " from "
                        + senderOfAck);

                // Try finding the specific track for key: FileID + "_" + SenderOfAck
                String trackingKey = fileIdForAck + "_" + senderOfAck;
                Map<Integer, CompletableFuture<Void>> fileAcks = pendingAcks.get(trackingKey);

                // Fallback for Private Chat (Legacy key was just fileId)
                if (fileAcks == null) {
                    fileAcks = pendingAcks.get(fileIdForAck);
                }

                if (fileAcks != null) {
                    CompletableFuture<Void> future = fileAcks.remove(idx);
                    if (future != null) {
                        future.complete(null);
                        System.out.println("[FLOW] Completed future for chunk " + idx);
                    } else {
                        System.out.println(
                                "[FLOW] No future found for chunk " + idx + " (Maybe already handled or timed out)");
                    }
                } else {
                    System.out.println("[FLOW] No active ACK tracking map found for file " + fileIdForAck);
                }
                break;
            case FILE_COMPLETE: {
                try {
                    String fileId = packet.getFileId();
                    System.out.println("[INTEGRITY] Received FILE_COMPLETE for " + packet.getFileName());

                    // Ensure file is closed if still held in activeDownloads (e.g. from resume)
                    RandomAccessFile raf = activeDownloads.get(fileId);
                    acceptedFileTransfers.remove(fileId); // Clean up for next time
                    activeDownloads.remove(fileId);
                    if (raf != null) {
                        try {
                            raf.getFD().sync();
                            raf.close();
                            System.out.println("[INTEGRITY] Closed active file handle for " + packet.getFileName());
                        } catch (Exception e) {
                            /* already closed or errored */ }
                    }

                    File downloadDir = new File("downloads");
                    File partFile = new File(downloadDir, packet.getFileName() + ".part");
                    File finalFile = new File(downloadDir, packet.getFileName());

                    if (partFile.exists()) {
                        String senderHash = new String(packet.getPayload());
                        String localHash = FileTransferUtil.calculateChecksum(partFile);

                        boolean match = senderHash.equalsIgnoreCase(localHash);
                        if (match) {
                            if (finalFile.exists())
                                finalFile.delete(); // Replace old version
                            boolean renamed = partFile.renameTo(finalFile);
                            String resultMsg = renamed
                                    ? "System: [INTEGRITY] '" + packet.getFileName() + "' Verified & Saved ✅"
                                    : "System: [INTEGRITY] '" + packet.getFileName()
                                            + "' Verified but Rename Failed ⚠️";
                            System.out.println(resultMsg);
                            final String targetKey = (packet.getGroup() != null) ? packet.getGroup()
                                    : packet.getSender();
                            Platform.runLater(() -> {
                                ChatWindowController chatWin = activeWindows.get(targetKey);
                                if (chatWin != null) {
                                    chatWin.appendChatMessage(resultMsg);
                                } else {
                                    controller.appendChat(resultMsg);
                                }
                            });
                        } else {
                            String errorMsg = "System: [INTEGRITY] '" + packet.getFileName()
                                    + "' CORRUPTED ❌ (Checksum Mismatch!)";
                            System.err.println(errorMsg);
                            final String targetKey = (packet.getGroup() != null) ? packet.getGroup()
                                    : packet.getSender();
                            Platform.runLater(() -> {
                                ChatWindowController chatWin = activeWindows.get(targetKey);
                                if (chatWin != null) {
                                    chatWin.appendChatMessage(errorMsg);
                                } else {
                                    controller.appendChat(errorMsg);
                                }
                            });
                        }
                    }
                } catch (Exception e) {
                    System.err.println("[INTEGRITY] Error during verification: " + e.getMessage());
                    e.printStackTrace();
                }
                break;
            }
            case RESUME_QUERY:
                handleResumeQuery(packet);
                break;

            case STATUS_UPDATE:
            case USER_LIST_QUERY:
            case GROUP_LIST_QUERY:
            case HEARTBEAT: // Heartbeat received, do nothing specific, just keeps connection alive
                break;

            case FILE_REQ: {
                // Someone wants to send us a file. Ask User.
                String snder = packet.getSender();
                String fName = packet.getFileName();
                String fId = packet.getFileId();
                String ctx = (packet.getGroup() != null) ? "Group " + packet.getGroup() : "Private Chat";

                Platform.runLater(() -> {
                    boolean accept = controller.showTrackableConfirmationAlert(fId, "File Request",
                            snder + " wants to send '" + fName + "' (" + (packet.getFileSize() / 1024) + " KB) in "
                                    + ctx + ".\nAccept?");

                    // Send Response
                    Packet resp = new Packet(PacketType.FILE_RESP, 2);
                    resp.setFileId(fId);
                    resp.setReceiver(snder); // Reply to sender
                    if (packet.getGroup() != null)
                        resp.setGroup(packet.getGroup());

                    if (accept) {
                        acceptedFileTransfers.add(fId); // <--- MARK AS ACCEPTED
                        resp.setPayload("YES".getBytes());
                        controller.appendChat("System: You accepted file '" + fName + "'");
                    } else {
                        acceptedFileTransfers.remove(fId); // Ensure removed
                        resp.setPayload("NO".getBytes());
                        controller.appendChat("System: You rejected file '" + fName + "'");
                    }
                    sendPacket(resp);
                });
                break;
            }

            case FILE_ABORT: {
                // Sender timed out or canceled.
                String fId = packet.getFileId();
                String fName = packet.getFileName();

                // CRITICAL FIX: Vanish the window automatically
                controller.closeAlert(fId);

                Platform.runLater(() -> {
                    controller.appendChat("System: Request for '" + fName + "' timed out (Too late to click YES).");
                });
                break;
            }

            case FILE_RESP: {
                // We asked, they answered.
                String fId = packet.getFileId();

                // 1. Check if this is a response to a Group Upload request
                if (pendingGroupUploads.containsKey(fId)) {
                    String ans = new String(packet.getPayload());
                    boolean approved = "YES".equalsIgnoreCase(ans);
                    String responder = packet.getSender(); // The user who clicked Yes/No

                    if (approved) {
                        System.out.println("[FLOW] User " + responder + " accepted group file " + fId
                                + ". Starting unicast thread...");
                        File fileToSend = pendingGroupUploads.get(fId);
                        String tId = pendingGroupTransactionIds.get(fId);

                        // Spawn a new thread for this specific receiver
                        new Thread(() -> {
                            try {
                                sendFileUnicast(fileToSend, responder, fId, tId);
                            } catch (Exception e) {
                                e.printStackTrace();
                                Platform.runLater(
                                        () -> controller.appendChat("System: Failed to send file to " + responder));
                            }
                        }).start();
                    } else {
                        System.out.println("[FLOW] User " + responder + " declined group file " + fId);
                        // We don't need to do anything, just don't start a thread.
                    }
                    return; // Done handling group response
                }

                // 2. Existing logic for Private Chats (Blocking Future)
                if (pendingFileRequests.containsKey(fId)) {
                    String ans = new String(packet.getPayload());
                    boolean approved = "YES".equalsIgnoreCase(ans);
                    pendingFileRequests.get(fId).complete(approved);
                }
                break;
            }
        }

    }

    public void sendPacket(Packet packet) {
        try {
            byte[] raw = serialize(packet);
            byte[] encrypted = CryptoUtil.encryptAES(raw, aesKey);
            synchronized (out) {
                ProtocolUtil.writePacket(out, encrypted);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendGroupMessage(String groupName, String message) {
        String transId = java.util.UUID.randomUUID().toString();
        byte[] fullPayload = message.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int chunkCount = (int) Math.ceil(fullPayload.length / 1024.0);
        if (chunkCount == 0)
            chunkCount = 1;

        for (int i = 0; i < chunkCount; i++) {
            int start = i * 1024;
            int end = Math.min(start + 1024, fullPayload.length);
            byte[] chunkData = (start < end) ? java.util.Arrays.copyOfRange(fullPayload, start, end) : new byte[0];

            Packet packet = new Packet(PacketType.GROUP_MESSAGE, 2);
            packet.setGroup(groupName);
            packet.setTransactionId(transId);
            packet.setChunkIndex(i);
            packet.setTotalChunks(chunkCount);
            packet.setPayload(chunkData);
            sendPacket(packet);
        }
    }

    private void processFullMessage(Packet packet) {
        if (packet.getPayload() == null)
            return;
        String msgPayload = new String(packet.getPayload(), java.nio.charset.StandardCharsets.UTF_8);
        Platform.runLater(() -> {
            if (packet.getType() == PacketType.DM) {
                try {
                    SecretKey key = e2eKeyMap.get(packet.getSender());
                    String decryptedMsg;
                    if (key != null) {
                        try {
                            byte[] decryptedBytes = CryptoUtil.decryptAES(packet.getPayload(), key);
                            decryptedMsg = new String(decryptedBytes, java.nio.charset.StandardCharsets.UTF_8);
                        } catch (Exception e) {
                            // Decryption failed - key mismatch? (Likely due to device switch)
                            System.err.println("[E2EE] Decryption failed for " + packet.getSender()
                                    + ". Re-initiating secure session...");
                            initiateE2E(packet.getSender());
                            decryptedMsg = "[SECURE MESSAGE - RE-ESTABLISHING SECURE CONNECTION...]";
                        }
                    } else {
                        decryptedMsg = msgPayload; // System messages aren't encrypted
                    }

                    // Detect forced disconnect message
                    if ("System".equals(packet.getSender())
                            && decryptedMsg.contains("logged in from another location")) {
                        forcedDisconnect = true;
                        System.out.println("[INFO] Detected forced disconnect. Auto-reconnect disabled.");
                    }

                    ChatWindowController chatWin = activeWindows.get(packet.getSender());
                    if (chatWin != null) {
                        chatWin.appendChatMessage(packet.getSender() + ": " + decryptedMsg);
                    } else {
                        controller.appendChat("🔒 [System] New DM from " + packet.getSender() + ": " + decryptedMsg);
                    }
                } catch (Exception e) {
                    controller.appendChat("[System] Failed to decrypt DM from " + packet.getSender());
                }
            } else if (packet.getType() == PacketType.GROUP_MESSAGE && packet.getGroup() != null) {
                ChatWindowController chatWin = activeWindows.get(packet.getGroup());
                if (chatWin != null) {
                    chatWin.appendChatMessage(packet.getSender() + ": " + msgPayload);
                } else {
                    controller.appendChat("System: New message in group " + packet.getGroup());
                }
            }
            System.out.println("Message reassembled for "
                    + (packet.getGroup() != null ? "group " + packet.getGroup() : "user " + packet.getSender()));
        });

    }

    public void registerChatWindow(String target, ChatWindowController win) {
        activeWindows.put(target, win);
    }

    public void unregisterChatWindow(String target) {
        activeWindows.remove(target);
    }

    public CompletableFuture<String> login(String username, String password) throws Exception {
        this.myUsername = username; // Set username upon successful login attempt
        this.lastUsername = username;
        this.lastPassword = password;
        String hashedPassword = ProtocolUtil.hashSHA256(password);
        Packet packet = new Packet(PacketType.LOGIN, 1);
        String payload = username + ":" + hashedPassword;
        packet.setPayload(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));

        loginFuture = new CompletableFuture<>();
        sendPacket(packet);
        return loginFuture;
    }

    public void sendFile(File file, String groupName) throws Exception {
        performFileTransfer(file, groupName, true);
    }

    public void sendDirectFile(File file, String username) throws Exception {
        performFileTransfer(file, username, false);
    }

    private void performFileTransfer(File file, String target, boolean isGroup) throws Exception {
        String fileId = ProtocolUtil.hashSHA256(file.getName() + file.length()); // Stable ID for resume
        long fileSize = file.length();
        int totalChunks = (int) Math.ceil((double) fileSize / FileTransferUtil.CHUNK_SIZE);
        if (totalChunks == 0 && fileSize == 0)
            totalChunks = 1;

        if (activeUploads.contains(fileId)) {
            Platform.runLater(() -> controller.appendChat("System: Upload already in progress for '" + file.getName()
                    + "'. Please wait for the current transfer or its timeout (30s)."));
            return;
        }

        // Generate transaction ID for this file transfer
        String transactionId = java.util.UUID.randomUUID().toString();

        try {
            // PARALLEL GROUP UPLOAD LOGIC
            if (isGroup) {
                // Store file reference for anytime acceptance
                pendingGroupUploads.put(fileId, file);
                pendingGroupTransactionIds.put(fileId, transactionId);

                // Send FILE_REQ (Broadcast)
                Packet req = new Packet(PacketType.FILE_REQ, 2);
                req.setSender(myUsername);
                req.setGroup(target);
                req.setFileId(fileId);
                req.setFileName(file.getName());
                req.setFileSize(fileSize);
                req.setTransactionId(transactionId);

                System.out.println("[FLOW] sending Group FILE_REQ for " + file.getName());
                Platform.runLater(() -> {
                    String msg = "System: Offered '" + file.getName() + "' to Group " + target;
                    controller.appendChat(msg);
                    ChatWindowController chatWin = activeWindows.get(target);
                    if (chatWin != null) {
                        chatWin.appendChatMessage(msg);
                    }
                });

                sendPacket(req);
                return; // RETURN IMMEDIATELY - Do not block, do not send data yet.
            }

            // --- PRIVATE CHAT LOGIC (Blocking Stop-and-Wait) ---

            // 1. Check for Resume (Standard logic)
            // ... (keep existing resume query logic for private chat if desired, currently
            // it's mixed)
            // For simplicity and safety, we'll run the standard private flow here as it
            // was.

            System.out.println("[RESUME] Querying server for existing progress of " + file.getName());
            CompletableFuture<Integer> resumeFuture = new CompletableFuture<>();
            String resumeTrackingKey = fileId + "_" + target;
            pendingResumeRequests.put(resumeTrackingKey, resumeFuture);

            Packet query = new Packet(PacketType.RESUME_QUERY, 1);
            query.setFileId(fileId);
            query.setFileName(file.getName());
            query.setReceiver(target);

            sendPacket(query);

            int lastChunkIndex = -1;
            try {
                lastChunkIndex = resumeFuture.get(2, TimeUnit.SECONDS);
                System.out.println("[RESUME] Peer reports last chunk received: " + lastChunkIndex);
            } catch (Exception e) {
                System.err.println("[RESUME] Timeout or error waiting for RESUME_INFO: " + e.getMessage());
            } finally {
                pendingResumeRequests.remove(resumeTrackingKey);
            }

            // Send FILE_REQ
            Packet req = new Packet(PacketType.FILE_REQ, 2);
            req.setSender(myUsername);
            req.setReceiver(target);
            req.setFileId(fileId);
            req.setFileName(file.getName());
            req.setFileSize(fileSize);
            req.setTransactionId(transactionId);

            System.out.println("[FLOW] Asking permission to send " + file.getName() + " to " + target);
            Platform.runLater(() -> {
                String msg = "System: Asking " + target + " for permission to send '" + file.getName() + "'...";
                controller.appendChat(msg);
                ChatWindowController chatWin = activeWindows.get(target);
                if (chatWin != null) {
                    chatWin.appendChatMessage(msg);
                }
            });

            CompletableFuture<Boolean> permissionFuture = new CompletableFuture<>();
            pendingFileRequests.put(fileId, permissionFuture);

            sendPacket(req);

            try {
                // Wait indefinitely for user response
                boolean approved = permissionFuture.get();
                if (!approved) {
                    System.out.println("[FLOW] Permission DENIED for " + file.getName());
                    Platform.runLater(() -> {
                        String msg = "System: Transfer denied by " + target;
                        controller.appendChat(msg);
                        ChatWindowController chatWin = activeWindows.get(target);
                        if (chatWin != null) {
                            chatWin.appendChatMessage(msg);
                        }
                    });
                    return;
                }
            } finally {
                pendingFileRequests.remove(fileId);
            }

            Platform.runLater(() -> {
                String msg = "System: Permission Granted! Starting upload of '" + file.getName() + "'";
                controller.appendChat(msg);
                ChatWindowController chatWin = activeWindows.get(target);
                if (chatWin != null) {
                    chatWin.appendChatMessage(msg);
                }
            });

            // Re-use the Unicast Logic for Private Chat too
            sendFileUnicast(file, target, fileId, transactionId);

        } finally {
            // For private chats we might remove activeUploads here, but for group uploads
            // the file needs to stay "available". Ideally we clear it on app close or some
            // management logic.
            // For now, we leave it in 'activeUploads' to prevent duplicate sends of SAME
            // file ID.
            if (!isGroup) {
                activeUploads.remove(fileId);
            }
        }
    }

    private void sendFileUnicast(File file, String targetReceiver, String fileId, String transactionId)
            throws Exception {
        long fileSize = file.length();
        int totalChunks = (int) Math.ceil((double) fileSize / FileTransferUtil.CHUNK_SIZE);
        if (totalChunks == 0 && fileSize == 0)
            totalChunks = 1;

        // 1. Resume Check (Per receiver)
        System.out.println("[RESUME] Querying peer " + targetReceiver + " for progress of " + file.getName());
        CompletableFuture<Integer> resumeFuture = new CompletableFuture<>();
        String resumeTrackingKey = fileId + "_" + targetReceiver;
        pendingResumeRequests.put(resumeTrackingKey, resumeFuture);

        Packet query = new Packet(PacketType.RESUME_QUERY, 1);
        query.setFileId(fileId);
        query.setFileName(file.getName());
        query.setReceiver(targetReceiver);
        sendPacket(query);

        int lastChunkIndex = -1;
        try {
            lastChunkIndex = resumeFuture.get(2, TimeUnit.SECONDS);
            System.out.println("[RESUME] Peer reports last chunk received: " + lastChunkIndex);
        } catch (Exception e) {
            System.err.println("[RESUME] Timeout or error waiting for RESUME_INFO: " + e.getMessage());
        } finally {
            pendingResumeRequests.remove(resumeTrackingKey);
        }

        // 2. Send FILE_INIT
        Packet init = new Packet(PacketType.FILE_INIT, 3);
        init.setSender(myUsername);
        init.setReceiver(targetReceiver);
        init.setFileId(fileId);
        init.setFileName(file.getName());
        init.setFileSize(fileSize);
        init.setTransactionId(transactionId);
        init.setTotalChunks(totalChunks);
        sendPacket(init);

        // 3. Setup ACK tracking
        String trackingKey = fileId + "_" + targetReceiver;
        pendingAcks.put(trackingKey, new ConcurrentHashMap<>());

        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file))) {
            int skipChunks = lastChunkIndex + 1;
            long skipBytes = (long) skipChunks * FileTransferUtil.CHUNK_SIZE;
            if (skipBytes > 0) {
                bis.skip(skipBytes);
                System.out.println("[FLOW] [RESUME] Skipping " + skipChunks + " already sent chunks.");
            }

            System.out.println("[FLOW] [Parallel-Stream] Starting transfer of " + file.getName() + " to "
                    + targetReceiver + " (Chunk " + (skipChunks + 1) + " to " + totalChunks + ")");
            byte[] buffer = new byte[FileTransferUtil.CHUNK_SIZE];
            int bytesRead;
            int chunkIndex = skipChunks;

            while ((bytesRead = bis.read(buffer)) != -1) {
                byte[] chunkData = (bytesRead < FileTransferUtil.CHUNK_SIZE)
                        ? java.util.Arrays.copyOf(buffer, bytesRead)
                        : buffer.clone();

                Packet chunk = new Packet(PacketType.FILE_CHUNK, 3);
                chunk.setReceiver(targetReceiver);
                chunk.setFileId(fileId);
                chunk.setFileName(file.getName());
                chunk.setChunkIndex(chunkIndex);
                chunk.setTotalChunks(totalChunks);
                chunk.setTransactionId(transactionId);
                chunk.setPayload(chunkData);

                // Retry Logic
                int retryCount = 0;
                boolean ackReceived = false;
                while (retryCount < 3 && !ackReceived) {
                    CompletableFuture<Void> ackFuture = new CompletableFuture<>();
                    pendingAcks.get(trackingKey).put(chunkIndex, ackFuture);

                    sendPacket(chunk);

                    try {
                        // Wait for ACK
                        ackFuture.get(10, TimeUnit.SECONDS);
                        ackReceived = true;
                    } catch (Exception e) {
                        retryCount++;
                        System.err.println("[FLOW] Timeout waiting for ACK " + chunkIndex + " from " + targetReceiver);
                        if (retryCount >= 3) {
                            Platform.runLater(
                                    () -> controller.appendChat("System: Drop " + targetReceiver + " (Timeout)"));
                            return;
                        }
                    } finally {
                        pendingAcks.get(trackingKey).remove(chunkIndex);
                    }
                }
                chunkIndex++;
            }

            // Send COMPLETE
            String finalHash = FileTransferUtil.calculateChecksum(file);
            Packet complete = new Packet(PacketType.FILE_COMPLETE, 1);
            complete.setReceiver(targetReceiver);
            complete.setFileId(fileId);
            complete.setFileName(file.getName());
            complete.setPayload(finalHash.getBytes());
            sendPacket(complete);

            Platform.runLater(() -> controller.appendChat("System: Finished sending to " + targetReceiver));

        } finally {
            pendingAcks.remove(trackingKey);
        }
    }

    private void handleKeyExchange(Packet packet) {
        String otherUser = packet.getSender();
        try {
            if (packet.getPayload() != null && packet.getPayload().length > 0) {
                // If we have a pending key, this is a response
                if (pendingDHKeys.containsKey(otherUser)) {
                    PrivateKey myPrivate = pendingDHKeys.remove(otherUser);
                    SecretKey sharedSecret = CryptoUtil.deriveSharedSecret(myPrivate, packet.getPayload());
                    e2eKeyMap.put(otherUser, sharedSecret);
                    Platform.runLater(() -> controller.appendChat("System: E2EE established with " + otherUser));

                    // Automatically send any pending messages once E2EE is established
                    flushPendingMessages(otherUser);
                } else {
                    // This is an INIT request
                    KeyPair kp = CryptoUtil.generateDHKeyPair();
                    SecretKey sharedSecret = CryptoUtil.deriveSharedSecret(kp.getPrivate(), packet.getPayload());
                    e2eKeyMap.put(otherUser, sharedSecret);

                    // Send RESPONSE
                    Packet response = new Packet(PacketType.KEY_EXCHANGE, 1);
                    response.setReceiver(otherUser);
                    response.setPayload(kp.getPublic().getEncoded());
                    sendPacket(response);
                    Platform.runLater(
                            () -> controller.appendChat("System: E2EE established with " + otherUser + " (Response)"));

                    // Automatically send any pending messages once E2EE is established
                    flushPendingMessages(otherUser);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            Platform.runLater(() -> controller.appendChat("Error in E2EE handshake: " + e.getMessage()));
        }
    }

    public void initiateE2E(String targetUser) {
        // Idempotency: Don't start another handshake if one is already pending or
        // established
        if (e2eKeyMap.containsKey(targetUser) || pendingDHKeys.containsKey(targetUser)) {
            return;
        }
        try {
            KeyPair kp = CryptoUtil.generateDHKeyPair();
            pendingDHKeys.put(targetUser, kp.getPrivate());

            Packet init = new Packet(PacketType.KEY_EXCHANGE, 1);
            init.setReceiver(targetUser);
            init.setPayload(kp.getPublic().getEncoded());
            sendPacket(init);
            Platform.runLater(() -> controller.appendChat("System: Initiated E2EE with " + targetUser + "..."));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void flushPendingMessages(String targetUser) {
        Queue<String> messages = pendingMessages.remove(targetUser);
        if (messages != null) {
            while (!messages.isEmpty()) {
                String msg = messages.poll();
                if (msg != null) {
                    sendSecureDM(targetUser, msg);
                }
            }
        }
    }

    public void sendSecureDM(String targetUser, String message) {
        try {
            SecretKey key = e2eKeyMap.get(targetUser);
            if (key == null) {
                // Buffer the message and initiate handshake if not already in progress
                pendingMessages.computeIfAbsent(targetUser, k -> new LinkedBlockingQueue<>()).add(message);
                initiateE2E(targetUser);
                Platform.runLater(() -> controller.appendChat("System: Securing connection with " + targetUser
                        + "... (Message will be sent automatically)"));
                return;
            }
            // Encrypt FULL message first, THEN chunk if needed
            byte[] encryptedFullMsg = CryptoUtil.encryptAES(message.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    key);
            String transId = java.util.UUID.randomUUID().toString();
            int chunkCount = (int) Math.ceil(encryptedFullMsg.length / 1024.0);
            if (chunkCount == 0)
                chunkCount = 1;

            for (int i = 0; i < chunkCount; i++) {
                int start = i * 1024;
                int end = Math.min(start + 1024, encryptedFullMsg.length);
                byte[] chunkData = java.util.Arrays.copyOfRange(encryptedFullMsg, start, end);

                Packet packet = new Packet(PacketType.DM, 1);
                packet.setReceiver(targetUser);
                packet.setTransactionId(transId);
                packet.setChunkIndex(i);
                packet.setTotalChunks(chunkCount);
                packet.setPayload(chunkData);
                sendPacket(packet);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void createGroup(String groupName) {
        Packet packet = new Packet(PacketType.GROUP_CREATE, 1);
        packet.setSender(myUsername);
        packet.setGroup(groupName);
        sendPacket(packet);
    }

    public void joinGroup(String groupName) {
        Packet packet = new Packet(PacketType.GROUP_JOIN, 1);
        packet.setSender(myUsername);
        packet.setGroup(groupName);
        sendPacket(packet);
    }

    public void updateStatus(String status) {
        if (myUsername == null)
            return;
        Packet packet = new Packet(PacketType.STATUS_UPDATE, 1);
        packet.setSender(myUsername);
        packet.setPayload(status.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        sendPacket(packet);
    }

    public void requestUserList() {
        Packet packet = new Packet(PacketType.USER_LIST_QUERY, 1);
        sendPacket(packet);
    }

    public void requestGroupList() {
        Packet packet = new Packet(PacketType.GROUP_LIST_QUERY, 1);
        sendPacket(packet);
    }

    private void handleResumeQuery(Packet packet) {
        String fileName = packet.getFileName();
        String fileId = packet.getFileId();
        if (fileName == null || fileId == null)
            return;

        File downloadDir = new File("downloads");
        File file = new File(downloadDir, fileName);
        File partFile = new File(downloadDir, fileName + ".part");

        int lastChunk = -1;
        if (file.exists()) {
            // Check if it's the SAME file (simplified size check)
            if (file.length() == packet.getFileSize()) {
                lastChunk = (int) Math.ceil((double) file.length() / FileTransferUtil.CHUNK_SIZE) - 1;
                System.out.println("[RESUME] File already completed: " + fileName);
            } else {
                System.out.println("[RESUME] File exists but size mismatch. Starting fresh.");
            }
        } else if (partFile.exists()) {
            long currentSize = partFile.length();
            lastChunk = (int) (currentSize / FileTransferUtil.CHUNK_SIZE) - 1;
            System.out.println("[RESUME] Partial file found: " + fileName + ".part (" + currentSize
                    + " bytes). Resuming from chunk: " + (lastChunk + 1));
        }

        Packet info = new Packet(PacketType.RESUME_INFO, 1);
        info.setFileId(fileId);
        info.setChunkIndex(lastChunk);
        info.setReceiver(packet.getSender());
        info.setSender(myUsername);
        sendPacket(info);
    }

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
}
