package io.getarrays.securecapita.form;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class NewPasswordForm {

    @NotNull(message = "ID cannot be null or empty")
    private Long userId;

    @NotEmpty(message = "First name cannot be empty")
    private String password;

    @NotEmpty(message = "Last name cannot be empty")
    private String confirmPassword;
}
