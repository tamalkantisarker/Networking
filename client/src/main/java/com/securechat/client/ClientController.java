package com.securechat.client;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.control.PasswordField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Region;
import javafx.stage.Stage;
import java.io.*;

public class ClientController {

    // Login View
    @FXML
    private TextField usernameField;
    @FXML
    private TextField serverIpField;
    @FXML
    private TextField serverPortField;
    @FXML
    private PasswordField passwordField;
    @FXML
    private Label statusLabel;

    // Chat View
    @FXML
    private ListView<String> groupList;
    @FXML
    private ListView<String> userListView;
    @FXML
    private ComboBox<String> statusComboBox;
    @FXML
    private ListView<HBox> chatListView;
    @FXML
    private Label currentUserLabel;

    private ClientApp app;
    private NetworkClient networkClient;

    public void setApp(ClientApp app) {
        this.app = app;
    }

    @FXML
    public void initialize() {
        if (groupList != null) {
            groupList.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, newVal) -> {
                if (newVal != null) {
                    openChatWindow(newVal, true);
                    Platform.runLater(() -> groupList.getSelectionModel().clearSelection());
                }
            });
        }
        if (userListView != null) {
            userListView.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, newVal) -> {
                if (newVal != null) {
                    // newVal is "username [● Online]"
                    String rawUsername = newVal.split(" \\[")[0];
                    if (!rawUsername.equals(currentUserLabel.getText())) {
                        openChatWindow(rawUsername, false);
                    }
                    Platform.runLater(() -> userListView.getSelectionModel().clearSelection());
                }
            });
        }

        if (statusComboBox != null) {
            statusComboBox.getItems().clear();
            statusComboBox.getItems().addAll("Online", "Busy", "Offline");
            statusComboBox.setValue("Online");
            statusComboBox.getSelectionModel().selectedItemProperty().addListener((obs, oldVal, newVal) -> {
                if (newVal != null && networkClient != null) {
                    new Thread(() -> networkClient.updateStatus(newVal)).start();
                }
            });
        }
    }

    @FXML
    private void handleLogin() {
        String username = usernameField.getText().trim();
        String password = passwordField.getText();
        String ip = serverIpField.getText().trim();
        String portStr = serverPortField.getText().trim();

        if (username.isEmpty()) {
            statusLabel.setText("Username cannot be empty.");
            return;
        }

        if (password.isEmpty()) {
            statusLabel.setText("Password cannot be empty.");
            return;
        }

        int port = 5000;
        try {
            if (!portStr.isEmpty()) {
                port = Integer.parseInt(portStr);
            }
        } catch (NumberFormatException e) {
            statusLabel.setText("Invalid port number.");
            return;
        }

        statusLabel.setText("Connecting...");

        int finalPort = port;
        new Thread(() -> {
            try {
                networkClient = new NetworkClient(ip, finalPort, this);
                networkClient.connect(username);

                // Give listener thread time to start
                Thread.sleep(1000);

                // Attempt login with password
                java.util.concurrent.CompletableFuture<String> loginFuture = networkClient.login(username, password);

                // Wait for response with timeout
                try {
                    String response = loginFuture.get(5, java.util.concurrent.TimeUnit.SECONDS);
                    String[] parts = response.split(":", 2);
                    boolean success = parts[0].equals("SUCCESS");
                    String message = parts.length > 1 ? parts[1] : "";

                    Platform.runLater(() -> {
                        if (success) {
                            app.setNetworkClient(networkClient);
                            try {
                                app.showChatView(username);
                            } catch (Exception e) {
                                statusLabel.setText("Error loading chat: " + e.getMessage());
                            }
                        } else {
                            statusLabel.setText("Login failed: " + message);
                        }
                    });
                } catch (java.util.concurrent.TimeoutException e) {
                    Platform.runLater(() -> statusLabel.setText("Login timeout - server not responding"));
                } catch (Exception e) {
                    Platform.runLater(() -> statusLabel.setText("Login error: " + e.getMessage()));
                }
            } catch (Exception e) {
                e.printStackTrace();
                Platform.runLater(() -> statusLabel.setText("Connection failed: " + e.getMessage()));
            }
        }).start();
    }

    private void openChatWindow(String target, boolean isGroup) {
        Platform.runLater(() -> {
            try {
                javafx.fxml.FXMLLoader loader = new javafx.fxml.FXMLLoader(
                        getClass().getResource("chat-window-view.fxml"));
                javafx.scene.Parent root = loader.load();
                ChatWindowController controller = loader.getController();

                Stage stage = new Stage();
                javafx.scene.Scene scene = new javafx.scene.Scene(root);
                stage.setScene(scene);

                controller.init(target, isGroup, networkClient, stage);
                networkClient.registerChatWindow(target, controller);

                if (isGroup) {
                    // Automatically join the group on the server when opening the window
                    new Thread(() -> {
                        try {
                            networkClient.joinGroup(target);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }).start();
                } else {
                    // Proactively initiate E2EE handshake for private chats
                    new Thread(() -> {
                        try {
                            networkClient.initiateE2E(target);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }).start();
                }

                stage.show();
            } catch (IOException e) {
                e.printStackTrace();
                appendChat("System: Failed to open chat window for " + target);
            }
        });
    }

    @FXML
    private void handleCreateGroup() {
        String groupName = showInputAlert("Create Group", "Enter group name:");
        if (groupName != null && !groupName.isEmpty() && networkClient != null) {
            new Thread(() -> networkClient.createGroup(groupName)).start();
        }
    }

    private String showInputAlert(String title, String content) {
        TextInputDialog dialog = new TextInputDialog();
        dialog.setTitle(title);
        dialog.setHeaderText(null);
        dialog.setContentText(content);
        java.util.Optional<String> result = dialog.showAndWait();
        return result.orElse(null);
    }

    public boolean showConfirmationAlert(String title, String content) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(content);
        java.util.Optional<ButtonType> result = alert.showAndWait();
        return result.isPresent() && result.get() == ButtonType.OK;
    }

    public void updateUserList(String data) {
        if (data == null || data.isEmpty())
            return;
        updateUserList(data.split("\\|"));
    }

    public void appendChat(String message) {
        Platform.runLater(() -> {
            if (chatListView != null) {
                HBox container = new HBox();
                Label label = new Label(message);
                label.setWrapText(true);
                label.setPrefWidth(Region.USE_COMPUTED_SIZE);
                label.setMaxWidth(400);

                if (message.startsWith("Me:")) {
                    container.setAlignment(Pos.CENTER_RIGHT);
                    label.getStyleClass().add("message-bubble-me");
                } else if (message.startsWith("---") || message.startsWith("System:")) {
                    container.setAlignment(Pos.CENTER);
                    label.setStyle("-fx-text-fill: #a6adc8; -fx-font-size: 11px;");
                } else {
                    container.setAlignment(Pos.CENTER_LEFT);
                    label.getStyleClass().add("message-bubble-other");
                }

                container.getChildren().add(label);
                chatListView.getItems().add(container);
                chatListView.scrollTo(chatListView.getItems().size() - 1);
            }
        });
    }

    public void updateGroupList(String[] groups) {
        Platform.runLater(() -> {
            if (groupList != null) {
                groupList.getItems().clear();
                if (groups != null) {
                    groupList.getItems().addAll(groups);
                }
            }
        });
    }

    public void updateUserList(String[] userEntries) {
        Platform.runLater(() -> {
            if (userListView != null) {
                userListView.getItems().clear();
            }

            if (userEntries != null) {
                for (String entry : userEntries) {
                    // entry is "username:status"
                    String[] parts = entry.split(":", 2);
                    String username = parts[0];
                    String status = parts.length > 1 ? parts[1] : "Online";

                    // Update the display list (Active Users) - show name and status with indicators
                    if (userListView != null) {
                        String indicator = "";
                        switch (status.toLowerCase()) {
                            case "online":
                                indicator = "●";
                                break;
                            case "away":
                                indicator = "◐";
                                break;
                            case "busy":
                                indicator = "⊘";
                                break;
                            case "offline":
                                indicator = "○";
                                break;
                        }
                        userListView.getItems().add(username + " [" + indicator + " " + status + "]");
                    }
                }
            }
        });
    }

    public void setUsername(String username) {
        if (currentUserLabel != null) {
            currentUserLabel.setText(username);
            currentUserLabel.setStyle("-fx-text-fill: black; -fx-font-weight: bold;");
        }
    }

    public void setNetworkClient(NetworkClient networkClient) {
        this.networkClient = networkClient;
    }

    public String getSelectedGroup() {
        return null; // Obsolete
    }

    public String getSelectedUser() {
        return null; // Obsolete
    }
}
