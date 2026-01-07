package com.securechat.server;

import com.securechat.common.crypto.CryptoUtil;
import com.securechat.common.protocol.Packet;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

public class ServerState {
    private static ServerState instance;

    // Security Identity
    private final KeyPair rsaKeyPair;

    // Connection State
    // Map<Username, ClientHandler>
    private final Map<String, ClientHandler> activeClients = new ConcurrentHashMap<>();
    private final Map<String, String> userStatuses = new ConcurrentHashMap<>(); // username -> status
    private final Map<String, String> userCredentials = new ConcurrentHashMap<>(); // username -> hashed password

    // Map<GroupName, Set<Username>>
    private final Map<String, Set<String>> groups = new ConcurrentHashMap<>();

    // Log Callback (Simple helper for UI)
    private java.util.function.Consumer<String> logCallback;
    private java.util.function.Consumer<String> networkLogCallback;
    private Runnable userChangeCallback;

    // Resume Support State
    // Map<FileId, Map<ReceiverUsername, LastChunkIndex>>
    private final Map<String, Map<String, Integer>> lstciTable = new ConcurrentHashMap<>();

    // High-Performance Priority Queue
    private final PriorityBlockingQueue<Packet> packetQueue;
    private final AtomicLong sequenceCounter = new AtomicLong(0);

    private ServerState() throws Exception {
        this.rsaKeyPair = CryptoUtil.generateRSAKeyPair();

        // PriorityBlockingQueue orders elements naturally if they implement Comparable.
        // Packet doesn't implement Comparable yet, need a comparator.
        // Lower priority number = Higher priority (1 > 2 > 3)
        // Secondary criteria: sequenceNumber for stable (FIFO) ordering within same
        // priority
        this.packetQueue = new PriorityBlockingQueue<>(1000, (p1, p2) -> {
            int priorityComp = Integer.compare(p1.getPriority(), p2.getPriority());
            if (priorityComp == 0) {
                return Long.compare(p1.getSequenceNumber(), p2.getSequenceNumber());
            }
            return priorityComp;
        });

        // Load persisted resume state
        loadLSTCI();
    }

    public static synchronized ServerState getInstance() {
        if (instance == null) {
            try {
                instance = new ServerState();
            } catch (Exception e) {
                throw new RuntimeException("Failed to initialize ServerState", e);
            }
        }
        return instance;
    }

    public KeyPair getRsaKeyPair() {
        return rsaKeyPair;
    }

    public void addClient(String username, ClientHandler handler) {
        ClientHandler oldHandler = activeClients.get(username);
        if (oldHandler != null && oldHandler != handler) {
            log("System: Primary session already exists for " + username + ". Forcing disconnect of old session.");
            oldHandler.forceDisconnect();
        }
        activeClients.put(username, handler);
    }

    public Map<String, ClientHandler> getConnectedUsers() {
        return activeClients;
    }

    public Map<String, Set<String>> getGroups() {
        return groups;
    }

    public PriorityBlockingQueue<Packet> getPacketQueue() {
        return packetQueue;
    }

    // Helper methods for Groups
    public void createGroup(String groupName) {
        groups.putIfAbsent(groupName, Collections.synchronizedSet(new HashSet<>()));
    }

    public void joinGroup(String groupName, ClientHandler client) {
        String username = client.getUsername();
        if (username == null)
            return;

        groups.compute(groupName, (k, members) -> {
            if (members == null) {
                members = Collections.synchronizedSet(new HashSet<>());
                System.out.println("[Logic] Auto-created group '" + groupName + "' for joiner " + username);
            }
            members.add(username);
            System.out.println("[Logic] " + username + " added to group '" + groupName
                    + "'. Total members: " + members.size());
            return members;
        });
    }

    public void leaveGroup(String groupName, ClientHandler client) {
        String username = client.getUsername();
        if (username == null)
            return;

        groups.computeIfPresent(groupName, (k, members) -> {
            members.remove(username);
            return members;
        });
    }

    /**
     * Helper to get list of groups a user is in.
     */
    public List<String> getUserGroups(ClientHandler client) {
        String username = client.getUsername();
        if (username == null)
            return new ArrayList<>();

        List<String> userGroups = new ArrayList<>();
        for (Map.Entry<String, Set<String>> entry : groups.entrySet()) {
            if (entry.getValue().contains(username)) {
                userGroups.add(entry.getKey());
            }
        }
        return userGroups;
    }

    // Resume Support Helpers
    public void updateLSTCI(String fileId, String receiver, int chunkIndex) {
        lstciTable.computeIfAbsent(fileId, k -> new ConcurrentHashMap<>())
                .put(receiver, chunkIndex);
        saveLSTCI();
    }

    public int getLSTCI(String fileId, String receiver) {
        return lstciTable.getOrDefault(fileId, Collections.emptyMap())
                .getOrDefault(receiver, -1);
    }

    public void setLogCallback(java.util.function.Consumer<String> callback) {
        this.logCallback = callback;
    }

    public void setNetworkLogCallback(java.util.function.Consumer<String> callback) {
        this.networkLogCallback = callback;
    }

    public boolean authenticate(String username, String hashedPassword) {
        if (!userCredentials.containsKey(username)) {
            userCredentials.put(username, hashedPassword);
            return true;
        }
        return userCredentials.get(username).equals(hashedPassword);
    }

    public void setUserStatus(String username, String status) {
        userStatuses.put(username, status);
    }

    public String getUserStatus(String username) {
        return userStatuses.getOrDefault(username, "Online");
    }

    public Map<String, String> getAllUserStatuses() {
        return new HashMap<>(userStatuses);
    }

    public void removeClient(String username, ClientHandler handler) {
        // Only remove if the current handler matches the one being cleaned up
        // This prevents old sessions from removing new sessions during cleanup
        activeClients.remove(username, handler);

        // Only remove status if this was the active handler
        if (!activeClients.containsKey(username)) {
            userStatuses.remove(username);
        }
    }

    public void log(String message) {
        System.out.println(message); // Always print to console
        if (logCallback != null) {
            logCallback.accept(message);
        }
    }

    public void logNetwork(String message) {
        System.out.println("[Network] " + message);
        if (networkLogCallback != null) {
            networkLogCallback.accept(message);
        }
    }

    public void setUserChangeCallback(Runnable callback) {
        this.userChangeCallback = callback;
    }

    public void notifyUserChange() {
        if (userChangeCallback != null) {
            userChangeCallback.run();
        }
    }

    public long getNextSequenceNumber() {
        return sequenceCounter.getAndIncrement();
    }

    public void enqueue(Packet packet) {
        packet.setSequenceNumber(getNextSequenceNumber());
        packetQueue.put(packet);
    }

    private void saveLSTCI() {
        try {
            java.util.Properties props = new java.util.Properties();
            for (Map.Entry<String, Map<String, Integer>> entry : lstciTable.entrySet()) {
                String fileId = entry.getKey();
                for (Map.Entry<String, Integer> inner : entry.getValue().entrySet()) {
                    String receiver = inner.getKey();
                    props.setProperty(fileId + ":" + receiver, String.valueOf(inner.getValue()));
                }
            }
            try (java.io.FileOutputStream fos = new java.io.FileOutputStream("resume_state.properties")) {
                props.store(fos, "File Transfer Resume State");
            }
        } catch (Exception e) {
            System.err.println("Failed to save resume state: " + e.getMessage());
        }
    }

    private void loadLSTCI() {
        java.io.File file = new java.io.File("resume_state.properties");
        if (!file.exists())
            return;

        try {
            java.util.Properties props = new java.util.Properties();
            try (java.io.FileInputStream fis = new java.io.FileInputStream(file)) {
                props.load(fis);
            }
            for (String key : props.stringPropertyNames()) {
                String[] parts = key.split(":", 2);
                if (parts.length == 2) {
                    String fileId = parts[0];
                    String receiver = parts[1];
                    int index = Integer.parseInt(props.getProperty(key));
                    lstciTable.computeIfAbsent(fileId, k -> new ConcurrentHashMap<>())
                            .put(receiver, index);
                }
            }
            System.out.println("Loaded " + props.size() + " resume states from disk.");
        } catch (Exception e) {
            System.err.println("Failed to load resume state: " + e.getMessage());
        }
    }
}
