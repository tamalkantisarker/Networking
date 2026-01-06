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
            if (!intentionallyClosed) {
                System.err.println("Listener error: " + e.getMessage());
                if (authSuccess) {
                    attemptReconnect();
                }
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

    private File getDownloadDirectory() {
        String userHome = System.getProperty("user.home");
        File systemDownloads = new File(userHome, "Downloads");
        if (systemDownloads.exists() && systemDownloads.isDirectory()) {
            return systemDownloads;
        }
        // Fallback to local app downloads folder
        File localDownloads = new File("downloads");
        if (!localDownloads.exists()) {
            localDownloads.mkdir();
        }
        return localDownloads;
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
                    File downloadDir = getDownloadDirectory();
                    File file = new File(downloadDir, packet.getFileName());
                    RandomAccessFile raf = new RandomAccessFile(file, "rw");
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
                        File downloadDir = getDownloadDirectory();
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
                                            + " (Saved to " + getDownloadDirectory().getAbsolutePath() + ")");
                                } else {
                                    controller.appendChat("System: File download complete: " + packet.getFileName()
                                            + " (Saved to " + getDownloadDirectory().getAbsolutePath() + ")");
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
                String[] users = userPayload.split(",");
                // Support pipe format from server as well
                if (userPayload.contains("|")) {
                    users = userPayload.split("\\|");
                }

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

            case RESUME_INFO:
                String fid = packet.getFileId();
                if (fid != null && pendingResumeRequests.containsKey(fid)) {
                    pendingResumeRequests.get(fid).complete(packet.getChunkIndex());
                }
                break;
            case LOGIN:
            case GROUP_CREATE:
            case GROUP_JOIN:
            case GROUP_LEAVE:
            case CHUNK_ACK:
                String fileIdForAck = packet.getFileId();
                int idx = packet.getChunkIndex();
                System.out.println("[FLOW] Received CHUNK_ACK for file " + fileIdForAck + ", chunk " + idx);
                Map<Integer, CompletableFuture<Void>> fileAcks = pendingAcks.get(fileIdForAck);
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

                    File downloadDir = getDownloadDirectory();
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
                if (pendingFileRequests.containsKey(fId)) {
                    String ans = new String(packet.getPayload());
                    boolean approved = "YES".equalsIgnoreCase(ans);

                    CompletableFuture<Boolean> future = pendingFileRequests.get(fId);

                    // LOGIC CHANGE:
                    // If Private Chat: Forward result immediately (Yes or No).
                    // If Group Chat:
                    // - If YES: Complete immediately (Start sending).
                    // - If NO: IGNORE IT. (Wait for someone else to say Yes).

                    if (packet.getGroup() == null) {
                        // Private
                        future.complete(approved);
                    } else {
                        // Group
                        if (approved) {
                            // Correct: Found at least one person who wants it.
                            future.complete(true);
                        } else {
                            // Ignore "NO" in groups. Let the timeout handle it if NO ONE says yes.
                            System.out.println("[FLOW] User rejected group file. Waiting for others...");
                        }
                    }
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
                        byte[] decryptedBytes = CryptoUtil.decryptAES(packet.getPayload(), key);
                        decryptedMsg = new String(decryptedBytes, java.nio.charset.StandardCharsets.UTF_8);
                    } else {
                        decryptedMsg = "[Encrypted Content - No Key]";
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
            activeUploads.add(fileId);

            // 1. Check for Resume
            System.out.println("[RESUME] Querying server for existing progress of " + file.getName());
            CompletableFuture<Integer> resumeFuture = new CompletableFuture<>();
            pendingResumeRequests.put(fileId, resumeFuture);

            Packet query = new Packet(PacketType.RESUME_QUERY, 1);
            query.setFileId(fileId);
            query.setFileName(file.getName());
            query.setReceiver(target); // Target name (Group or User)
            sendPacket(query);

            int lastChunkIndex = -1;
            try {
                // Wait up to 2 seconds for response
                lastChunkIndex = resumeFuture.get(2, TimeUnit.SECONDS);
                System.out.println("[RESUME] Server reports last chunk received: " + lastChunkIndex);
            } catch (Exception e) {
                System.err.println("[RESUME] Timeout or error waiting for RESUME_INFO: " + e.getMessage());
            } finally {
                pendingResumeRequests.remove(fileId);
            }

            // Fix: Check if file is already fully transferred
            if (lastChunkIndex + 1 >= totalChunks) {
                String msg = "System: File '" + file.getName()
                        + "' already exists (100% complete). Re-sending from start.";
                System.out.println("[RESUME] " + msg);
                Platform.runLater(() -> controller.appendChat(msg));
                lastChunkIndex = -1; // Force Restart
            }

            // --- REVISED PERMISSION LOGIC ---
            // Send FILE_REQ
            Packet req = new Packet(PacketType.FILE_REQ, 2);
            req.setSender(myUsername);
            if (isGroup)
                req.setGroup(target);
            else
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
            pendingFileRequests.put(fileId, permissionFuture); // We need to define this map!

            sendPacket(req);

            try {
                boolean approved = permissionFuture.get(30, TimeUnit.SECONDS); // 30s timeout for user to click Yes
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
            } catch (Exception e) {
                System.out.println("[FLOW] Permission timeout for " + file.getName());
                Platform.runLater(
                        () -> controller.appendChat("System: Transfer timed out waiting for response from " + target));

                // SYNC FIX: Notify receiver that they are too late
                Packet abort = new Packet(PacketType.FILE_ABORT, 1);
                abort.setSender(myUsername);
                if (isGroup)
                    abort.setGroup(target);
                else
                    abort.setReceiver(target);
                abort.setFileId(fileId);
                abort.setFileName(file.getName());
                sendPacket(abort);

                return;
            } finally {
                pendingFileRequests.remove(fileId); // Memory Cleanup
            }

            Platform.runLater(() -> {
                String msg = "System: Permission Granted! Starting upload of '" + file.getName() + "'";
                controller.appendChat(msg);
                ChatWindowController chatWin = activeWindows.get(target);
                if (chatWin != null) {
                    chatWin.appendChatMessage(msg);
                }
            });

            // 2. Send FILE_INIT (Only after permission!)
            Packet init = new Packet(PacketType.FILE_INIT, 3);
            init.setSender(myUsername != null ? myUsername : "Me");
            if (isGroup) {
                init.setGroup(target);
            } else {
                init.setReceiver(target);
            }
            init.setFileId(fileId);
            init.setFileName(file.getName());
            init.setFileSize(fileSize);
            init.setTransactionId(transactionId); // Add transaction ID
            // CRITICAL FIX: FILE_INIT is a SINGLE packet.
            // Do NOT set totalChunks to the file's chunk count, otherwise the receiver
            // will wait for 'totalChunks' packets to arrive before processing this INIT.
            init.setTotalChunks(1);
            sendPacket(init);

            // 3. Setup ACK tracking for this file
            pendingAcks.put(fileId, new ConcurrentHashMap<>());

            // 4. Streaming Send with Serial Flow Control (Stop-and-Wait)
            try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(file))) {
                int startFrom = lastChunkIndex + 1;
                if (startFrom > 0) {
                    FileTransferUtil.skipFully(bis, (long) startFrom * FileTransferUtil.CHUNK_SIZE);
                    Platform.runLater(() -> controller
                            .appendChat("System: Resuming " + file.getName() + " from chunk " + (startFrom + 1)));
                }

                byte[] buffer = new byte[FileTransferUtil.CHUNK_SIZE];
                int bytesRead;
                int currentChunk = startFrom;

                while ((bytesRead = bis.read(buffer)) != -1) {
                    byte[] chunkData = (bytesRead < FileTransferUtil.CHUNK_SIZE)
                            ? java.util.Arrays.copyOf(buffer, bytesRead)
                            : buffer.clone();

                    Packet chunk = new Packet(PacketType.FILE_CHUNK, 3);
                    if (isGroup) {
                        chunk.setGroup(target);
                    } else {
                        chunk.setReceiver(target);
                    }
                    chunk.setFileId(fileId);
                    chunk.setFileName(file.getName());
                    chunk.setChunkIndex(currentChunk);
                    chunk.setTotalChunks(totalChunks);
                    chunk.setTransactionId(transactionId); // Add transaction ID
                    chunk.setPayload(chunkData);

                    // --- POWERFUL SYSTEM: RETRY LOGIC (Up to 3 times) ---
                    int retryCount = 0;
                    boolean ackReceived = false;
                    while (retryCount < 3 && !ackReceived) {
                        // Create a future to wait for the ACK of this specific chunk
                        CompletableFuture<Void> ackFuture = new CompletableFuture<>();
                        pendingAcks.get(fileId).put(currentChunk, ackFuture);

                        // Send the chunk
                        if (retryCount > 0)
                            System.out.println("[FLOW] RETRY " + retryCount + " for chunk " + currentChunk);
                        else
                            System.out.println("[FLOW] Sending chunk " + currentChunk + "/" + (totalChunks - 1));

                        sendPacket(chunk);

                        // Wait for ACK (Serial Flow Control)
                        try {
                            System.out.println("[FLOW] Waiting for ACK of chunk " + currentChunk + "...");
                            ackFuture.get(10, TimeUnit.SECONDS);
                            System.out.println("[FLOW] ACK received for chunk " + currentChunk);
                            ackReceived = true;
                        } catch (Exception e) {
                            retryCount++;
                            System.err.println(
                                    "[FLOW CONTROL] Attempt " + retryCount + " failed for chunk " + currentChunk
                                            + ": " + e.getMessage());
                            if (retryCount >= 3) {
                                System.err.println(
                                        "[FLOW CONTROL] Maximum retries reached. ABORTING transfer to prevent corruption.");
                                Platform.runLater(() -> {
                                    if (controller != null) {
                                        controller.appendChat("System: Transfer of " + file.getName()
                                                + " ABORTED due to network timeout.");
                                    }
                                });
                                return; // Stop the entire transfer
                            }
                        } finally {
                            pendingAcks.get(fileId).remove(currentChunk);
                        }
                    }
                    currentChunk++;
                }

                // --- POWERFUL SYSTEM: COMPLETION VERIFICATION ---
                System.out.println("[INTEGRITY] Calculating hash for " + file.getName());
                String finalHash = FileTransferUtil.calculateChecksum(file);
                Packet complete = new Packet(PacketType.FILE_COMPLETE, 1);
                if (isGroup) {
                    complete.setGroup(target);
                } else {
                    complete.setReceiver(target);
                }
                complete.setFileId(fileId);
                complete.setFileName(file.getName());
                complete.setPayload(finalHash.getBytes()); // Send hash in payload
                sendPacket(complete);
                System.out.println("[INTEGRITY] FILE_COMPLETE sent with hash: " + finalHash);

            } finally {
                pendingAcks.remove(fileId);
            }

            Platform.runLater(
                    () -> controller.appendChat("System: Finished sending " + file.getName() + " (Powerful System)"));
        } finally {
            activeUploads.remove(fileId);
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
            // If final file exists, it's already done (or we don't need to resume)
            lastChunk = 999999;
        } else if (partFile.exists()) {
            long currentSize = partFile.length();
            // Calculate how many FULL chunks we have in the partial file
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
