package com.tistory.ospace.simplesecurity3.entity;

import java.time.LocalDateTime;

public class Response {
    private LocalDateTime timestamp;
    private Integer status;
    private String error;
    private String message;
    private String path;
    
    public static Response of (Integer status, String error, String message, String path) {
        return new Response(status, error, message, path);
    }
    
    private Response (Integer status, String error, String message, String path) {
        this.status = status;
        this.error = error;
        this.message =  message;
        this.path = path;
        this.timestamp = LocalDateTime.now();
    }
    
    public LocalDateTime getTimestamp() {
        return timestamp;
    }
    public Integer getStatus() {
        return status;
    }
    public String getError() {
        return error;
    }
    public String getMessage() {
        return message;
    }
    public String getPath() {
        return path;
    }
    @Override
    public String toString() {
        return "Response [timestamp=" + timestamp + ", status=" + status
                + ", error=" + error + ", message=" + message + ", path=" + path
                + "]";
    }
}
