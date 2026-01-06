package com.securechat.client;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class ClientApp extends Application {

    private Stage stage;
    private NetworkClient networkClient;

    public NetworkClient getNetworkClient() {
        return networkClient;
    }

    public void setNetworkClient(NetworkClient networkClient) {
        this.networkClient = networkClient;
    }

    @Override
    public void start(Stage stage) throws IOException {
        this.stage = stage;
        stage.setOnCloseRequest(e -> System.exit(0)); // Terminate all background threads on exit
        showLoginView();
    }

    public void showLoginView() throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(ClientApp.class.getResource("login-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load());

        ClientController controller = fxmlLoader.getController();
        controller.setApp(this);

        stage.setTitle("SecureChat - Login");
        stage.setScene(scene);

        // Manual Maximization Strategy
        javafx.geometry.Rectangle2D bounds = javafx.stage.Screen.getPrimary().getVisualBounds();
        stage.setX(bounds.getMinX());
        stage.setY(bounds.getMinY());
        stage.setWidth(bounds.getWidth());
        stage.setHeight(bounds.getHeight());
        stage.setMaximized(true);

        stage.show();
    }

    public void showChatView(String username) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(ClientApp.class.getResource("chat-view.fxml"));
        Scene scene = new Scene(fxmlLoader.load());

        ClientController controller = fxmlLoader.getController();
        controller.setApp(this);
        controller.setUsername(username);

        if (networkClient != null) {
            networkClient.setController(controller);
            controller.setNetworkClient(networkClient);
            networkClient.requestUserList();
            networkClient.requestGroupList();
        }

        stage.setTitle("SecureChat - " + username);
        stage.setScene(scene);

        // Robust Maximization for Chat View
        javafx.geometry.Rectangle2D bounds = javafx.stage.Screen.getPrimary().getVisualBounds();
        stage.setX(bounds.getMinX());
        stage.setY(bounds.getMinY());
        stage.setWidth(bounds.getWidth());
        stage.setHeight(bounds.getHeight());
        stage.setMaximized(true);

        stage.show();
        // Force it again after show just in case
        javafx.application.Platform.runLater(() -> stage.setMaximized(true));
    }

    public static void main(String[] args) {
        launch();
    }
}
