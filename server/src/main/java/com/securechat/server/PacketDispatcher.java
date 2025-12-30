package com.securechat.server;

import com.securechat.common.protocol.Packet;
import com.securechat.common.protocol.PacketType;

import java.util.Set;

public class PacketDispatcher implements Runnable {

    private final ServerState serverState;
    private boolean running = true;

    public PacketDispatcher() {
        this.serverState = ServerState.getInstance();
    }

    @Override
    public void run() {
        System.out.println("PacketDispatcher started.");
        while (running) {
            try {
                // Take packet from Priority Queue (Blocking)
                Packet packet = serverState.getPacketQueue().take();
                processPacket(packet);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                System.err.println("Error processing packet: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    private void processPacket(Packet packet) {
        PacketType type = packet.getType();

        // Route based on type
        switch (type) {
            case DM:
                checkPriorityBypass(packet);
                routeDirectly(packet);
                break;
            case KEY_EXCHANGE:
            case RESUME_QUERY:
                routeDirectly(packet);
                break;
            case FILE_INIT:
            case FILE_REQ:
            case FILE_CHUNK:
            case FILE_COMPLETE:
                if (packet.getGroup() != null) {
                    routeToGroup(packet);
                } else {
                    routeDirectly(packet);
                }
                break;
            case FILE_RESP:
                routeDirectly(packet);
                break;

            case GROUP_MESSAGE:
                checkPriorityBypass(packet);
                routeToGroup(packet);
                break;

            case CHUNK_ACK:
            case DM_ACK:
            case GROUP_ACK:
            case RESUME_INFO:
                if (type == PacketType.DM_ACK) {
                    serverState.log("[ACK] DM_ACK for " + packet.getReceiver() + " from " + packet.getSender());
                } else if (type == PacketType.GROUP_ACK) {
                    serverState.log("[Broadcast ACK] Reassembled by " + packet.getSender() + " for group "
                            + packet.getGroup());
                }
                routeDirectly(packet);
                break;

            case GROUP_LIST_UPDATE:
                // These are usually broadcasts, route based on target if present, otherwise
                // ignore
                if (packet.getReceiver() != null) {
                    routeDirectly(packet);
                } else if (packet.getGroup() != null) {
                    routeToGroup(packet);
                }
                break;

            case STATUS_UPDATE:
            case USER_LIST_QUERY:
            case HEARTBEAT:
                // Silently ignore as these are already handled as Control Packets
                break;

            default:
                System.out.println("Dispatcher ignored packet type: " + type);
        }
    }

    private void checkPriorityBypass(Packet packet) {
        int bypassed = 0;
        for (Packet p : serverState.getPacketQueue()) {
            if (p.getType() == PacketType.FILE_CHUNK) {
                bypassed++;
            }
        }
        if (bypassed > 0) {
            String msg = String.format(
                    "*** TRAFFIC SHAPING ACTIVE ***\n" +
                            "   [Congestion Control] High Priority Packet (%s, P%d) SKIPPED AHEAD of %d queued File Chunks.\n"
                            +
                            "   Status: Prioritizing real-time chat over background file transfer.",
                    packet.getType(), packet.getPriority(), bypassed);
            serverState.logNetwork(msg);
        }
    }

    private void routeDirectly(Packet packet) {
        String receiverName = packet.getReceiver();
        if (receiverName == null)
            return;

        ClientHandler receiver = serverState.getConnectedUsers().get(receiverName);
        if (receiver != null) {
            // Universal Logging for all packet types that carry data/progress
            String typeLabel = switch (packet.getType()) {
                case FILE_INIT -> "File Init";
                case FILE_REQ -> "File Req";
                case FILE_RESP -> "File Resp";
                case FILE_CHUNK -> "File Chunk";
                case FILE_COMPLETE -> "File Complete";
                case CHUNK_ACK -> "ACK";
                case DM -> "DM";
                case RESUME_INFO -> "Resume Info";
                case KEY_EXCHANGE -> "Key Exchange";
                default -> "Data";
            };

            String logMsg = String.format("Routing %s [%d/%d] from %s to %s",
                    typeLabel, (packet.getChunkIndex() + 1), packet.getTotalChunks(),
                    packet.getSender(), packet.getReceiver());

            // Add transaction ID if present (for file transfers and messages)
            if (packet.getTransactionId() != null) {
                // logMsg += " [Trans: " + packet.getTransactionId() + "]"; // Verbose trans ID
                // removed
            }

            // Universal Logging enabled as requested to show Flow Control (Chunk/ACK)
            serverState.logNetwork(logMsg);
            receiver.sendPacket(packet);
        } else {
            System.out.println("User not found: " + receiverName);
        }
    }

    private void routeToGroup(Packet packet) {
        String groupName = packet.getGroup();
        if (groupName == null)
            return;

        Set<ClientHandler> members = serverState.getGroups().get(groupName);
        if (members != null) {
            // Universal Logging for all packet types that carry data/progress
            String typeLabel = switch (packet.getType()) {
                case FILE_INIT -> "File Init";
                case FILE_REQ -> "File Req";
                case FILE_RESP -> "File Resp";
                case FILE_CHUNK -> "File Chunk";
                case FILE_COMPLETE -> "File Complete";
                case CHUNK_ACK -> "ACK";
                case GROUP_MESSAGE -> "Group Msg";
                case RESUME_INFO -> "Resume Info";
                case KEY_EXCHANGE -> "Key Exchange";
                case DM -> "DM (in Group?)";
                default -> "Data";
            };

            String logMsg = String.format("Broadcasting %s [%d/%d] from %s to Group %s",
                    typeLabel, (packet.getChunkIndex() + 1), packet.getTotalChunks(),
                    packet.getSender(), groupName);

            serverState.logNetwork(logMsg);

            synchronized (members) {
                for (ClientHandler member : members) {
                    if (!member.getUsername().equals(packet.getSender())) {
                        member.sendPacket(packet);
                    }
                }
            }
        }
    }

    public void stop() {
        running = false;
    }
}
