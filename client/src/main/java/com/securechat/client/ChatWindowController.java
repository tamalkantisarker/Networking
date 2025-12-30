package com.securechat.client;

import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.layout.Region;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;

public class ChatWindowController {

    @FXML
    private Label chatTitleLabel;
    @FXML
    private ScrollPane chatScrollPane;
    @FXML
    private VBox chatVBox;
    @FXML
    private TextField messageField;
    @FXML
    private Button attachButton;

    private String targetName; // Username or GroupName
    private boolean isGroup;
    private NetworkClient networkClient;
    private Stage stage;

    public void init(String targetName, boolean isGroup, NetworkClient networkClient, Stage stage) {
        this.targetName = targetName;
        this.isGroup = isGroup;
        this.networkClient = networkClient;
        this.stage = stage;

        chatTitleLabel.setText(isGroup ? "Group Chat: " + targetName : "Private Chat with: " + targetName);
        stage.setTitle(chatTitleLabel.getText());

        stage.setOnCloseRequest(event -> {
            if (networkClient != null) {
                networkClient.unregisterChatWindow(targetName);
            }
        });
    }

    @FXML
    private void handleSendMessage() {
        String msg = messageField.getText().trim();
        if (msg.isEmpty())
            return;

        if (networkClient != null) {
            if (isGroup) {
                networkClient.sendGroupMessage(targetName, msg);
            } else {
                networkClient.sendSecureDM(targetName, msg);
            }
        }

        appendChatMessage("Me: " + msg);
        messageField.clear();
    }

    @FXML
    private void handleSendFile() {
        if (networkClient == null)
            return;

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select File to Send");
        File file = fileChooser.showOpenDialog(stage);

        if (file != null) {
            new Thread(() -> {
                try {
                    if (isGroup) {
                        networkClient.sendFile(file, targetName);
                    } else {
                        networkClient.sendDirectFile(file, targetName);
                    }
                } catch (Exception e) {
                    Platform.runLater(() -> appendChatMessage("System: Failed to send file: " + e.getMessage()));
                }
            }).start();
        }
    }

    @FXML
    private void handleOpenDownloads() {
        try {
            File downloadDir = new File("downloads");
            if (!downloadDir.exists()) {
                downloadDir.mkdir();
            }
            java.awt.Desktop.getDesktop().open(downloadDir);
        } catch (Exception e) {
            appendChatMessage("System: Failed to open downloads folder: " + e.getMessage());
        }
    }

    @FXML
    private void addEmoji(javafx.event.ActionEvent event) {
        if (event.getSource() instanceof Button) {
            Button btn = (Button) event.getSource();
            messageField.appendText(btn.getText());
            messageField.requestFocus();
        }
    }

    public void appendChatMessage(String message) {
        Platform.runLater(() -> {
            HBox container = new HBox();
            Label label = new Label(message);
            label.setWrapText(true);
            label.setPrefWidth(Region.USE_COMPUTED_SIZE);
            label.setMaxWidth(400);

            if (message.startsWith("Me:")) {
                container.setAlignment(Pos.CENTER_RIGHT);
                label.getStyleClass().add("message-bubble-me");
                label.setStyle(
                        "-fx-background-color: #0078d4; -fx-text-fill: white; -fx-background-radius: 10; -fx-padding: 8;");
            } else if (message.startsWith("System:")) {
                container.setAlignment(Pos.CENTER);
                label.setStyle("-fx-text-fill: grey; -fx-font-size: 11px;");
            } else {
                container.setAlignment(Pos.CENTER_LEFT);
                label.setStyle(
                        "-fx-background-color: #e9e9eb; -fx-text-fill: black; -fx-background-radius: 10; -fx-padding: 8;");
            }

            container.getChildren().add(label);
            chatVBox.getChildren().add(container);

            // Smooth auto-scroll to bottom
            // Force layout recalculation before scrolling
            chatVBox.layout();
            chatScrollPane.layout();

            // Scroll to bottom smoothly (1.0 = 100% = bottom)
            chatScrollPane.setVvalue(1.0);
        });
    }
}
