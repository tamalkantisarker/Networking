package com.securechat.server;

import com.securechat.common.protocol.Packet;
import com.securechat.common.protocol.PacketType;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ServerApp extends Application {
    private static final int PORT = 5000;

    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(ServerApp.class.getResource("server-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load());
        stage.setTitle("SecureChat Server");
        stage.setScene(scene);
        stage.setMaximized(true);
        stage.setOnCloseRequest(e -> System.exit(0)); // Kill threads on close
        stage.show();

        // Start Backend Threads
        startServerBackend();
    }

    private void startServerBackend() {
        ServerState state = ServerState.getInstance();
        state.log("Starting backend services...");

        // Start Dispatcher
        Thread dispatcherThread = new Thread(new PacketDispatcher());
        dispatcherThread.setDaemon(true);
        dispatcherThread.start();

        // Start TCP Acceptor
        Thread acceptorThread = new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(PORT)) {
                state.log("Server listening on port " + PORT);

                while (true) {
                    Socket clientSocket = serverSocket.accept();
                    state.log("New connection from " + clientSocket.getInetAddress());

                    ClientHandler handler = new ClientHandler(clientSocket);
                    new Thread(handler).start();
                }
            } catch (Exception e) {
                e.printStackTrace();
                Platform.runLater(() -> state.log("Server error: " + e.getMessage()));
            }
        });
        acceptorThread.setDaemon(true);
        acceptorThread.setDaemon(true);
        acceptorThread.start();

        // Start Heartbeat Service (Checks every 3 seconds)
        Thread heartbeatThread = new Thread(() -> {
            Packet heartbeat = new Packet(PacketType.HEARTBEAT, 1);
            while (true) {
                try {
                    Thread.sleep(3000);
                    state.getConnectedUsers().values().forEach(client -> {
                        // This calls sendPacket. If it fails, client is removed.
                        client.sendPacket(heartbeat);
                    });
                } catch (InterruptedException e) {
                    break;
                } catch (Exception e) {
                    // ignore iteration errors
                }
            }
        });
        heartbeatThread.setDaemon(true);
        heartbeatThread.start();
    }

    public static void main(String[] args) {
        launch();
    }
}
