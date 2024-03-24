package io.getarrays.securecapita.events;

import io.getarrays.securecapita.enumeration.EventType;
import lombok.Getter;
import lombok.Setter;
import org.springframework.context.ApplicationEvent;

@Setter
@Getter
public class NewUserEvent extends ApplicationEvent {
    private String email;
    private EventType type;

    public NewUserEvent(EventType type, String email) {
        super(email);
        this.email = email;
        this.type = type;

    }
}
