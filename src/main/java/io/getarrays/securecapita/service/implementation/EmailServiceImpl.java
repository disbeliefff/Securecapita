package io.getarrays.securecapita.service.implementation;

import io.getarrays.securecapita.enumeration.VerificationType;
import io.getarrays.securecapita.exception.ApiException;
import io.getarrays.securecapita.service.EmailService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import static java.lang.String.format;
import static org.apache.commons.lang3.StringUtils.capitalize;

@Service
@Slf4j
@AllArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    @Override
    public void sendVerificationEmail
            (String firstName, String email, String verificationUrl, VerificationType verificationType) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();

            message.setFrom("email@gmail.com");
            message.setTo(email);
            message.setText(getEmailMessage(firstName, verificationUrl, verificationType));
            message.setSubject(format("SecureCapita - %s Verification Email", capitalize(verificationType.getType())));

            log.info("Email sent to {}", firstName);
            mailSender.send(message);

        } catch (Exception exception) {
            log.error(exception.getMessage());
        }
    }

    private String getEmailMessage(String firstName, String verificationUrl, VerificationType verificationType) {
        switch (verificationType) {
            case PASSWORD -> {
                return "Hello " + firstName +
                        "\n\nReset password request. Please click the link bellow to verify your account. \n\n" +
                       verificationUrl + "\n\nThe support team.";
            }
            case ACCOUNT -> {
                return "Hello" + firstName +
                        "\n\nYour new account has been created. Please click the link below to verify your account. \n\n" +
                        verificationUrl + "\n\nThe support team.";
            }
            default -> throw new ApiException("Unable to sent email. Email type is unknown");
        }
    }
}
