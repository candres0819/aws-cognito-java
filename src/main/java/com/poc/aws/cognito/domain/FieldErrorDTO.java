package com.poc.aws.cognito.domain;

import java.io.Serial;
import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@Getter
@ToString
@AllArgsConstructor
public class FieldErrorDTO implements Serializable {

    @Serial
    private static final long serialVersionUID = -8619947059150751384L;
    private String field;
    private String message;

}
