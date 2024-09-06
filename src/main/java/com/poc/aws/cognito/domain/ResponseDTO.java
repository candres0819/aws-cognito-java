package com.poc.aws.cognito.domain;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class ResponseDTO<T> implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private int status;
    private String responseCode;
    private String responseMessage;
    private List<FieldErrorDTO> fieldErrors;
    private T data;
    @JsonIgnore
    private String user;

    public ResponseDTO() {
        // Empty constructor
    }

    public ResponseDTO(int status, String responseCode, String responseMessage, List<FieldErrorDTO> fieldErrors, T data) {
        this.status = status;
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
        this.fieldErrors = fieldErrors;
        this.data = data;
    }

    public ResponseDTO(int status, String responseCode, String responseMessage, List<FieldErrorDTO> fieldErrors) {
        this(status, responseCode, responseMessage, fieldErrors, null);
    }

    public ResponseDTO(int status, String responseCode, String responseMessage, T data) {
        this(status, responseCode, responseMessage, null, data);
    }

    public ResponseDTO(int status, String responseCode, String responseMessage) {
        this(status, responseCode, responseMessage, null, null);
    }

    public int getStatus() {
        return status;
    }

    public String getResponseCode() {
        return responseCode;
    }

    public String getResponseMessage() {
        return responseMessage;
    }

    public List<FieldErrorDTO> getFieldErrors() {
        return fieldErrors;
    }

    public T getData() {
        return data;
    }

    /**
     * @return the user
     */
    public String getUser() {
        return user;
    }

    /**
     * @param user
     *            the user to set
     */
    public void setUser(String user) {
        this.user = user;
    }

    @Override
    public String toString() {
        return "ResponseDto [status=" + status + ", responseCode=" + responseCode + ", responseMessage=" + responseMessage
                + ", fieldErrors=" + fieldErrors + ", data=" + data + "]";
    }
}