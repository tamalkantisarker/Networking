package com.securechat.common.protocol;

import java.io.Serializable;

public class Packet implements Serializable, Comparable<Packet> {
    private static final long serialVersionUID = 1L;

    // Header
    private PacketType type;
    private int priority; // 1: Control/DM, 2: Group, 3: File
    private String sender;
    private String receiver; // For DM or Resume
    private String group; // For Group Chat
    private String transactionId; // Unique ID to link chunks of the same message/file
    private long sequenceNumber; // For stable ordering in PriorityQueue

    // File Metadata (Optional/Contextual)
    private String fileId;
    private String fileName;
    private long fileSize;
    private int chunkIndex;
    private int totalChunks;

    // Payload
    private byte[] payload; // Encrypted data or raw content depending on stage

    public Packet(PacketType type, int priority) {
        this.type = type;
        this.priority = priority;
        this.chunkIndex = 0; // Default: first chunk
        this.totalChunks = 1; // Default: single chunk message
    }

    @Override
    public int compareTo(Packet other) {
        // Lower priority number = Higher priority (1 > 2 > 3)
        int priorityComp = Integer.compare(this.priority, other.priority);
        if (priorityComp == 0) {
            // Secondary criteria: sequenceNumber for stable (FIFO) ordering within same
            // priority
            return Long.compare(this.sequenceNumber, other.sequenceNumber);
        }
        return priorityComp;
    }

    // Getters and Setters
    public PacketType getType() {
        return type;
    }

    public void setType(PacketType type) {
        this.type = type;
    }

    public int getPriority() {
        return priority;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    public String getSender() {
        return sender;
    }

    public void setSender(String sender) {
        this.sender = sender;
    }

    public String getReceiver() {
        return receiver;
    }

    public void setReceiver(String receiver) {
        this.receiver = receiver;
    }

    public String getGroup() {
        return group;
    }

    public void setGroup(String group) {
        this.group = group;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
    }

    public long getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(long sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public String getFileId() {
        return fileId;
    }

    public void setFileId(String fileId) {
        this.fileId = fileId;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public long getFileSize() {
        return fileSize;
    }

    public void setFileSize(long fileSize) {
        this.fileSize = fileSize;
    }

    public int getChunkIndex() {
        return chunkIndex;
    }

    public void setChunkIndex(int chunkIndex) {
        this.chunkIndex = chunkIndex;
    }

    public int getTotalChunks() {
        return totalChunks;
    }

    public void setTotalChunks(int totalChunks) {
        this.totalChunks = totalChunks;
    }

    public byte[] getPayload() {
        return payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = payload;
    }
}
