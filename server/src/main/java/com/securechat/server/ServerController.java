package com.securechat.server;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.ScrollPane;
import javafx.scene.layout.VBox;
import javafx.scene.layout.Region; // For spacer if needed, but padding works
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;

public class ServerController {

    @FXML
    private ScrollPane logScrollPane;
    @FXML
    private VBox logVBox;

    // CHANGED: Using ListView instead of VBox for Virtualization and High
    // Performance
    @FXML
    private ListView<String> networkHealthListView;

    @FXML
    private ScrollPane userScrollPane;
    @FXML
    private VBox userVBox;

    @FXML
    private Label ipLabel;

    private ServerState serverState;

    @FXML
    public void initialize() {
        serverState = ServerState.getInstance();

        // 1. Setup Custom Cell Factory for ListView to look like Cards
        networkHealthListView.setCellFactory(listView -> new ListCell<String>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                if (empty || item == null) {
                    setGraphic(null);
                    setText(null);
                    setStyle("-fx-background-color: transparent;");
                } else {
                    // Create the Card UI
                    Label label = new Label(item);
                    label.setWrapText(true);
                    label.setMaxWidth(Double.MAX_VALUE); // Allow it to fill width
                    label.getStyleClass().add("card-item"); // Apply the CSS Card Style
                    label.setStyle("-fx-text-fill: #333333;"); // FORCE Dark Text Visibility

                    // We set the label as the graphic of the cell
                    setGraphic(label);
                    setText(null);

                    // Ensure the cell background itself is transparent so the spacing works
                    // visually
                    setStyle("-fx-background-color: transparent; -fx-padding: 2 5;");
                }
            }
        });

        // Register log callbacks
        serverState.setLogCallback(this::appendLog);
        serverState.setNetworkLogCallback(this::logNetworkEvent);
        serverState.setUserChangeCallback(this::updateUserList);

        appendLog("Server GUI Initialized.");
        updateUserList();
        displayServerIp();
    }

    private void displayServerIp() {
        try {
            StringBuilder ips = new StringBuilder("Server IP: ");
            boolean first = true;
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp())
                    continue;

                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr.getHostAddress().contains(":"))
                        continue; // Skip IPv6
                    if (!first)
                        ips.append(" | ");
                    ips.append(iface.getDisplayName()).append(": ").append(addr.getHostAddress());
                    first = false;
                }
            }
            Platform.runLater(() -> ipLabel.setText(ips.toString()));
        } catch (Exception e) {
            Platform.runLater(() -> ipLabel.setText("Server IP: Unknown"));
        }
    }

    public void logNetworkEvent(String event) {
        Platform.runLater(() -> {
            // Add to ListView items list
            networkHealthListView.getItems().add(event);

            // Updated Limit: 1,000,000 items (Very Robust)
            if (networkHealthListView.getItems().size() > 1000000) {
                networkHealthListView.getItems().remove(0);
            }

            // Auto-scroll to the bottom
            networkHealthListView.scrollTo(networkHealthListView.getItems().size() - 1);
        });
    }

    public void appendLog(String message) {
        Platform.runLater(() -> {
            Label label = new Label(message);
            label.setWrapText(true);
            label.getStyleClass().add("card-item"); // Apply Card Style
            logVBox.getChildren().add(label);

            // Keep traditional log short for cleanliness, but network log is massive now
            if (logVBox.getChildren().size() > 500) {
                logVBox.getChildren().remove(0);
            }

            // Smooth scroll to bottom
            logVBox.layout();
            logScrollPane.layout();
            logScrollPane.setVvalue(1.0);
        });
    }

    public void updateUserList() {
        Platform.runLater(() -> {
            userVBox.getChildren().clear();
            for (String user : serverState.getConnectedUsers().keySet()) {
                String status = serverState.getUserStatus(user);
                Label label = new Label(user + " (" + status + ")");
                label.setWrapText(true);
                label.getStyleClass().add("card-item"); // Apply Card Style
                // Add specific style for status if needed, but card-item handles the base look
                userVBox.getChildren().add(label);
            }
        });
    }
}
